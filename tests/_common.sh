#!/usr/bin/env bash
set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
PASS_COUNT=0; FAIL_COUNT=0
log_ok()   { printf "${GREEN}  [PASS]${RESET} %s\n" "$*"; }
log_fail() { printf "${RED}  [FAIL]${RESET} %s\n" "$*"; }
log_info() { printf "${YELLOW}  [INFO]${RESET} %s\n" "$*"; }
assert() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then log_ok "$d"; PASS_COUNT=$((PASS_COUNT+1)); else log_fail "$d"; FAIL_COUNT=$((FAIL_COUNT+1)); fi; }
assert_fail() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then log_fail "$d"; FAIL_COUNT=$((FAIL_COUNT+1)); else log_ok "$d"; PASS_COUNT=$((PASS_COUNT+1)); fi; }
assert_contains() { local d="$1" o="$2" p="$3"; if echo "$o"|grep -qE "$p"; then log_ok "$d"; PASS_COUNT=$((PASS_COUNT+1)); else log_fail "$d (expected: $p)"; FAIL_COUNT=$((FAIL_COUNT+1)); fi; }
assert_not_contains() { local d="$1" o="$2" p="$3"; if echo "$o"|grep -qE "$p"; then log_fail "$d (unexpected: $p)"; FAIL_COUNT=$((FAIL_COUNT+1)); else log_ok "$d"; PASS_COUNT=$((PASS_COUNT+1)); fi; }

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; PLUGIN_DIR="$(cd "$TESTS_DIR/.." && pwd)"
_find_workspace() { local d="$PLUGIN_DIR"; if [[ -d "$d/../../.qlab" ]]; then echo "$(cd "$d/../.." && pwd)"; return; fi; while [[ "$d" != "/" ]]; do if [[ -d "$d/.qlab" ]]; then echo "$d"; return; fi; d="$(dirname "$d")"; done; echo ""; }

WORKSPACE_DIR="$(_find_workspace)"
if [[ -z "$WORKSPACE_DIR" ]]; then echo "ERROR: Cannot find qlab workspace."; exit 1; fi
STATE_DIR="$WORKSPACE_DIR/.qlab/state"; SSH_KEY="$WORKSPACE_DIR/.qlab/ssh/qlab_id_rsa"
_get_port() { local f="$STATE_DIR/${1}.port"; if [[ -f "$f" ]]; then cat "$f"; else echo ""; fi; }

DEFENDER_PORT="$(_get_port cyber-lab-defender)"
ATTACKER_PORT="$(_get_port cyber-lab-attacker)"
if [[ -z "$DEFENDER_PORT" || -z "$ATTACKER_PORT" ]]; then echo "ERROR: Cannot find VM ports. Are cyber-lab VMs running?"; exit 1; fi

# Internal-LAN IPs (as configured in run.sh). The tests speak to these, not to
# forwarded host ports: the point is traffic that carries the attacker's real IP.
DEFENDER_IP="192.168.100.1"
ATTACKER_IP="192.168.100.2"

# IdentitiesOnly=yes + IdentityAgent=none: use ONLY the workspace key. Without
# this, a populated ssh-agent offers its keys first and can trip the VM's
# MaxAuthTries ("Too many authentication failures") before our key is tried.
_ssh_base_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o IdentitiesOnly=yes -o IdentityAgent=none)
ssh_defender() { ssh "${_ssh_base_opts[@]}" -i "$SSH_KEY" -p "$DEFENDER_PORT" labuser@localhost "$@"; }
ssh_attacker() { ssh "${_ssh_base_opts[@]}" -i "$SSH_KEY" -p "$ATTACKER_PORT" labuser@localhost "$@"; }

report_results() { local t="${1:-Test}"; echo ""; if [[ "$FAIL_COUNT" -eq 0 ]]; then printf "${GREEN}${BOLD}  %s: All %d checks passed${RESET}\n" "$t" "$PASS_COUNT"; else printf "${RED}${BOLD}  %s: %d passed, %d failed${RESET}\n" "$t" "$PASS_COUNT" "$FAIL_COUNT"; fi; return "$FAIL_COUNT"; }
