#!/usr/bin/env bash
# Chapter: "La raffica e il ban" — the ban is the proof.
#
# This is the invariant the whole plugin exists to make measurable:
# a running fail2ban is NOT a defense. The defense is proven only by
#   (1) the ban appearing in the register, keyed to the attacker's REAL IP, and
#   (2) the attacker actually locked out at the packet level afterwards.
#
# Deliberately absent: any check of 'systemctl is-active fail2ban'. A green on
# that would be the exact mistake this lab teaches against.
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

echo ""; echo "${BOLD}  Chapter — the ban is the proof${RESET}"; echo ""

# --- Preconditions: both hosts up, defender sees the attacker on the LAN ---
assert "defender reachable" ssh_defender "echo ok"
assert "attacker reachable" ssh_attacker "echo ok"
assert "attacker and defender share the internal LAN" \
    ssh_attacker "ping -c1 -W3 $DEFENDER_IP"

# fail2ban must be watching sshd — but note we assert it can PRODUCE a ban,
# not merely that the unit is active. If the jail is not even loaded, the
# later ban assertion would fail anyway; this just gives a clearer message.
jail0=$(ssh_defender "sudo fail2ban-client status 2>/dev/null" || true)
assert_contains "sshd jail is loaded on the defender" "$jail0" "sshd"

# --- Baseline: the door is open to the attacker, and nobody is banned yet ---
assert "BEFORE: attacker can reach defender:22" \
    ssh_attacker "nc -w3 -z $DEFENDER_IP 22"
status_before=$(ssh_defender "sudo fail2ban-client status sshd 2>/dev/null" || true)
assert_not_contains "BEFORE: attacker IP is not banned yet" "$status_before" "$ATTACKER_IP"
log_info "Baseline banned list: $(echo "$status_before" | grep -i 'banned ip' || echo '(none)')"

# --- The attack: a burst of failed logins from the attacker ---
log_info "Firing the burst from the attacker..."
ssh_attacker "burst-ssh $DEFENDER_IP 8" || true

# Give fail2ban a moment to read the journal and install the DROP rule.
log_info "Waiting for fail2ban to react..."
for _i in $(seq 1 12); do
    s=$(ssh_defender "sudo fail2ban-client status sshd 2>/dev/null" || true)
    echo "$s" | grep -q "$ATTACKER_IP" && break
    sleep 3
done

# --- Proof #1: the ban is in the register, keyed to the attacker's REAL IP ---
status_after=$(ssh_defender "sudo fail2ban-client status sshd 2>/dev/null" || true)
assert_contains "AFTER: fail2ban banned the attacker's real IP ($ATTACKER_IP)" \
    "$status_after" "$ATTACKER_IP"
log_info "Post-attack banned list: $(echo "$status_after" | grep -i 'banned ip' || echo '(none)')"

# --- Proof #2: the ban is EFFECTIVE — the attacker is locked out ---
# nc must now fail: the packets are dropped, not merely a log line written.
assert_fail "AFTER: attacker can NO LONGER reach defender:22 (ban is effective)" \
    ssh_attacker "nc -w3 -z $DEFENDER_IP 22"

# --- The contrast the lesson lives on: the service was 'active' the whole time.
# 'active' told us nothing; the ban and the lockout told us everything. ---
active=$(ssh_defender "systemctl is-active fail2ban 2>/dev/null" || true)
log_info "For contrast — 'systemctl is-active fail2ban' says: '$active' (this alone proves nothing)"

report_results "Chapter: the ban is the proof"
