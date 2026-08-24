#!/usr/bin/env bash
# Chapter: "DMARC says reject."
#
# Chapter 5 rejected the spoof with SPF. This one proves DMARC does it on its
# own, and for the fuller reason: the domain publishes _dmarc p=reject, and the
# forged mail neither passes SPF (wrong IP) nor carries a valid DKIM signature
# aligned to the From: domain — so DMARC fails and opendmarc rejects.
#
# To show it is DMARC and not the earlier SPF policy, we turn the SPF policy OFF
# and let opendkim+opendmarc be the only thing standing.
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

FROM=ceo@boss.lab
TO=victim@mail.lab

echo ""; echo "${BOLD}  Chapter — DMARC says reject${RESET}"; echo ""

# The milters must be alive for this chapter to mean anything.
assert "opendkim is running" ssh_defender "systemctl is-active --quiet opendkim"
assert "opendmarc is running" ssh_defender "systemctl is-active --quiet opendmarc"
dmarc_rec=$(ssh_defender "getent hosts _dmarc.boss.lab >/dev/null 2>&1; true; python3 -c \"import socket\" 2>/dev/null; true" || true)

# --- Undefended: SPF policy OFF and DMARC OFF → the forged mail is accepted ---
ssh_defender "sudo /usr/local/bin/mail-spf-off; sudo /usr/local/bin/mail-dmarc-off" >/dev/null 2>&1 || true
sleep 2
out_off=$(ssh_attacker "spoof-mail $FROM $TO $DEFENDER_IP" 2>&1 || true)
assert_contains "UNDEFENDED (no SPF policy, no DMARC): forged mail accepted (250)" "$out_off" "(^|[^0-9])250"

# --- DMARC ON (SPF policy still OFF) → rejected BY DMARC ---
log_info "Enforcing DMARC only (opendkim+opendmarc; SPF policy left off)..."
ssh_defender "sudo /usr/local/bin/mail-dmarc-on" >/dev/null 2>&1 || true
sleep 3
out_on=$(ssh_attacker "spoof-mail $FROM $TO $DEFENDER_IP" 2>&1 || true)
assert_contains "DEFENDED by DMARC alone: the SAME forged mail is rejected (5xx)" "$out_on" "(^|[^0-9])5[0-9][0-9]"
assert_contains "the rejection is attributed to DMARC" "$out_on" "[Dd][Mm][Aa][Rr][Cc]"

# Restore the sane default: SPF policy on, DMARC milters off (chapter 5 state).
ssh_defender "sudo /usr/local/bin/mail-dmarc-off; sudo /usr/local/bin/mail-spf-on" >/dev/null 2>&1 || true

report_results "Chapter: DMARC says reject"
