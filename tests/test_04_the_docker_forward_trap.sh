#!/usr/bin/env bash
# Chapter: "The firewall that wasn't — the Docker/FORWARD trap."
#
# You turn ufw on and deny a port. ufw says active, the rule is there, you feel
# safe. But the port belongs to a Docker-published container: its traffic is
# DNAT'd and FORWARDED, and never passes through INPUT where ufw's rule lives.
# So the attacker still gets in. The proof of a firewall is not 'ufw status
# = active'; it is the attacker actually blocked. (This is the 2026-08-19 VPS
# lesson: ufw does not protect ports published by Docker.)
#
# This test manages ufw entirely within itself and cleans up at the end, so it
# does not disturb the other chapters.
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

TRAP_PORT=8888

cleanup() {
    ssh_defender "sudo /usr/local/bin/docker-forward-unfix >/dev/null 2>&1; sudo ufw --force disable >/dev/null 2>&1" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ""; echo "${BOLD}  Chapter — the firewall that wasn't (Docker/FORWARD)${RESET}"; echo ""

# Precondition: the published container answers at all.
assert "the Docker-published port is up (container running)" \
    ssh_attacker "curl -s -o /dev/null --max-time 5 http://$DEFENDER_IP:$TRAP_PORT"

# Start clean, then raise ufw the way one normally would: allow ssh + web,
# DENY the container port, turn it on.
ssh_defender "sudo /usr/local/bin/docker-forward-unfix >/dev/null 2>&1; \
              sudo ufw --force reset >/dev/null 2>&1; \
              sudo ufw allow 22/tcp >/dev/null 2>&1; \
              sudo ufw allow 8080/tcp >/dev/null 2>&1; \
              sudo ufw deny ${TRAP_PORT}/tcp >/dev/null 2>&1; \
              sudo ufw --force enable >/dev/null 2>&1; echo up" >/dev/null 2>&1 || true
sleep 3

# The 'defense' is nominally in place: ufw active AND denying the port.
ufw_status=$(ssh_defender "sudo ufw status" 2>/dev/null || true)
assert_contains "ufw reports active" "$ufw_status" "Status: active"
assert_contains "ufw has a DENY rule for the container port" "$ufw_status" "${TRAP_PORT}.*(DENY|DENY IN)"

# THE TRAP: despite ufw active + deny, the attacker still reaches the port.
assert "TRAP: attacker STILL reaches :$TRAP_PORT despite ufw deny (ufw is on INPUT; the traffic is FORWARDED)" \
    ssh_attacker "curl -s -o /dev/null --max-time 5 http://$DEFENDER_IP:$TRAP_PORT"

# THE FIX, where the traffic actually is: a DROP in DOCKER-USER (FORWARD path).
log_info "Applying the fix: a DROP in DOCKER-USER (not in ufw/INPUT)..."
ssh_defender "sudo /usr/local/bin/docker-forward-fix" >/dev/null 2>&1 || true
sleep 1

# PROOF: now the attacker is actually blocked.
assert_fail "AFTER the DOCKER-USER fix, attacker can NO LONGER reach :$TRAP_PORT" \
    ssh_attacker "curl -s -o /dev/null --max-time 5 http://$DEFENDER_IP:$TRAP_PORT"

# For contrast: ufw was 'active' the whole time and it changed nothing.
log_info "For contrast — ufw was 'active' throughout; 'active' was never the question."

report_results "Chapter: the firewall that wasn't"
