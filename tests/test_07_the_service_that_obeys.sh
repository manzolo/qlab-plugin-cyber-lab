#!/usr/bin/env bash
# Chapter: "The service that obeys — a vulnerable protocol that isn't HTTP."
#
# Ported from the old cybersecurity-lab: a raw-TCP service on :9000 that runs
# whatever you send it (exec) and reads whatever path you name (file). The same
# close-it-and-prove-it loop as the web chapter, but over a hand-rolled protocol
# — the point being that a defence tuned to HTTP never even sees this traffic.
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

PORT=9000
# helper: send commands to the TCP service from the attacker and print the reply
_tcp() { ssh_attacker "printf '%b' '$1' | nc -w4 $DEFENDER_IP $PORT"; }

echo ""; echo "${BOLD}  Chapter — the service that obeys (raw TCP)${RESET}"; echo ""

# Start from the VULNERABLE state (idempotent).
ssh_defender "sudo rm -f /etc/cyber-lab/tcp-hardened; sudo systemctl restart cyber-tcp" >/dev/null 2>&1 || true
for _i in $(seq 1 8); do
    ssh_attacker "nc -w3 -z $DEFENDER_IP $PORT" >/dev/null 2>&1 && break || true
    sleep 2
done

assert "the TCP service answers on :$PORT" ssh_attacker "nc -w3 -z $DEFENDER_IP $PORT"

# --- Exploit: exec runs a command on the server; file reads any path ---
rce=$(_tcp 'exec id\nquit\n' 2>&1 || true)
assert_contains "RCE: 'exec id' runs on the server (uid=)" "$rce" "uid="
trav=$(_tcp 'file /etc/passwd\nquit\n' 2>&1 || true)
assert_contains "traversal: 'file /etc/passwd' leaks the file" "$trav" "root:.*:0:0:"

# --- Harden, then RESTART so the change takes effect ---
log_info "Hardening the service (touch /etc/cyber-lab/tcp-hardened; restart cyber-tcp)..."
ssh_defender "sudo mkdir -p /etc/cyber-lab && sudo touch /etc/cyber-lab/tcp-hardened && sudo systemctl restart cyber-tcp" >/dev/null 2>&1 || true
for _i in $(seq 1 8); do
    ssh_attacker "nc -w3 -z $DEFENDER_IP $PORT" >/dev/null 2>&1 && break || true
    sleep 2
done

# --- Prove the SAME attacks now fail ---
rce2=$(_tcp 'exec id\nquit\n' 2>&1 || true)
assert_not_contains "after hardening, exec no longer runs commands" "$rce2" "uid="
assert_contains "after hardening, exec is explicitly refused" "$rce2" "refused"
trav2=$(_tcp 'file /etc/passwd\nquit\n' 2>&1 || true)
assert_not_contains "after hardening, traversal no longer leaks /etc/passwd" "$trav2" "root:.*:0:0:"

# Leave it vulnerable for the next reader / re-run.
ssh_defender "sudo rm -f /etc/cyber-lab/tcp-hardened; sudo systemctl restart cyber-tcp" >/dev/null 2>&1 || true

report_results "Chapter: the service that obeys"
