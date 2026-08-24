#!/usr/bin/env bash
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"
SKIP_TESTS=()
while [[ $# -gt 0 ]]; do case "$1" in --skip) shift; SKIP_TESTS+=("$1"); shift ;; *) echo "Unknown: $1"; exit 1 ;; esac; done
should_skip() { local n="$1"; for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do [[ "$n" == "$s" ]] && return 0; done; return 1; }

echo ""; echo "${BOLD}=========================================${RESET}"; echo "${BOLD}  cyber-lab — Automated Test Suite${RESET}"; echo "${BOLD}=========================================${RESET}"; echo ""
log_info "Defender VM port: $DEFENDER_PORT  (internal IP $DEFENDER_IP)"
log_info "Attacker VM port: $ATTACKER_PORT  (internal IP $ATTACKER_IP)"
assert "Defender VM reachable" ssh_defender "echo ok"; assert "Attacker VM reachable" ssh_attacker "echo ok"
d_ci=$(ssh_defender "cloud-init status 2>/dev/null || echo done") || true; assert_contains "Defender cloud-init done" "$d_ci" "done"
a_ci=$(ssh_attacker "cloud-init status 2>/dev/null || echo done") || true; assert_contains "Attacker cloud-init done" "$a_ci" "done"

# fail2ban's activation phase can lag cloud-init "done"; give it a few tries.
log_info "Waiting for fail2ban on the defender to be ready..."
for _i in $(seq 1 8); do
    ssh_defender "sudo fail2ban-client status sshd" >/dev/null 2>&1 && break || true
    sleep 5
done
log_info "Waiting for the web app (cyber-web) to answer..."
for _i in $(seq 1 8); do
    ssh_attacker "curl -s -o /dev/null http://$DEFENDER_IP:8080" >/dev/null 2>&1 && break || true
    sleep 5
done
log_info "Waiting for the Docker-published container (:8888) to answer..."
for _i in $(seq 1 18); do
    ssh_attacker "curl -s -o /dev/null --max-time 4 http://$DEFENDER_IP:8888" >/dev/null 2>&1 && break || true
    sleep 5
done
log_info "Waiting for the mail server (:25) to answer..."
for _i in $(seq 1 12); do
    ssh_attacker "nc -w4 -z $DEFENDER_IP 25" >/dev/null 2>&1 && break || true
    sleep 5
done
log_info "Waiting for the raw-TCP service (:9000) to answer..."
for _i in $(seq 1 10); do
    ssh_attacker "nc -w3 -z $DEFENDER_IP 9000" >/dev/null 2>&1 && break || true
    sleep 3
done

TOTAL_PASS=0; TOTAL_FAIL=0; TESTS_RUN=0; TESTS_SKIPPED=0; FAILED_EXERCISES=()
run_test() { local n="$1"; local f=($TESTS_DIR/test_${n}_*.sh); [[ ! -f "${f[0]}" ]] && return; should_skip "$n" && { log_info "Skipping $n"; TESTS_SKIPPED=$((TESTS_SKIPPED+1)); return; }; local e=0; bash "${f[0]}" || e=$?; TESTS_RUN=$((TESTS_RUN+1)); if [[ "$e" -ne 0 ]]; then TOTAL_FAIL=$((TOTAL_FAIL+1)); FAILED_EXERCISES+=("$n"); else TOTAL_PASS=$((TOTAL_PASS+1)); fi; }

run_test "01"; run_test "02"; run_test "03"; run_test "04"; run_test "05"; run_test "06"; run_test "07"; run_test "08"

echo ""; echo "${BOLD}=========================================${RESET}"; echo "${BOLD}  Final Report${RESET}"; echo "${BOLD}=========================================${RESET}"; echo ""
echo "  Exercises run:     $TESTS_RUN"; echo "  Exercises passed:  $TOTAL_PASS"; echo "  Exercises failed:  $TOTAL_FAIL"; echo "  Exercises skipped: $TESTS_SKIPPED"
if [[ "$TOTAL_FAIL" -gt 0 ]]; then printf "\n${RED}${BOLD}  FAILED exercises: %s${RESET}\n" "${FAILED_EXERCISES[*]}"; exit 1; else printf "\n${GREEN}${BOLD}  All exercises passed!${RESET}\n"; exit 0; fi
