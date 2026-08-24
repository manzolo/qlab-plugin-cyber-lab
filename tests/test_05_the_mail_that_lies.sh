#!/usr/bin/env bash
# Chapter: "The mail that lies — SPF/DMARC."
#
# The attacker sends a mail claiming to be ceo@boss.lab. boss.lab's published
# SPF authorises one address that is NOT the attacker (and ends in -all); its
# DMARC says p=reject. So the claim is checkable, and false. The invariant, in
# the same attack/harden/prove shape as the web chapter:
#   - undefended (no SPF policy): the forged sender is ACCEPTED (250),
#   - defended (SPF policy on):   the SAME forged sender is REJECTED (550),
#     and the rejection cites SPF.
# The proof is the SMTP reply the attacker gets, not "postfix is active".
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

FROM=ceo@boss.lab
TO=victim@mail.lab

echo ""; echo "${BOLD}  Chapter — the mail that lies (SPF/DMARC)${RESET}"; echo ""

# Precondition: Postfix answers on the internal LAN.
assert "the mail server answers on the LAN (:25)" \
    ssh_attacker "nc -w4 -z $DEFENDER_IP 25"
# And the spoofable domain's SPF record is actually being served.
spf=$(ssh_defender "dig +short TXT boss.lab @127.0.0.1 2>/dev/null || host -t TXT boss.lab 127.0.0.1 2>/dev/null" || true)
log_info "boss.lab SPF as served: $(echo "$spf" | tr -d '\n')"

# --- Undefended: turn the policy OFF, send the forged mail, expect ACCEPT ---
ssh_defender "sudo /usr/local/bin/mail-spf-off" >/dev/null 2>&1 || true
sleep 2
out_off=$(ssh_attacker "spoof-mail $FROM $TO $DEFENDER_IP" 2>&1 || true)
assert_contains "UNDEFENDED: the forged sender is accepted (250)" "$out_off" "(^|[^0-9])250"

# --- Defended: turn SPF enforcement ON, send the SAME mail, expect REJECT ---
log_info "Enforcing SPF on the defender (mail-spf-on)..."
ssh_defender "sudo /usr/local/bin/mail-spf-on" >/dev/null 2>&1 || true
sleep 2
out_on=$(ssh_attacker "spoof-mail $FROM $TO $DEFENDER_IP" 2>&1 || true)
assert_contains "DEFENDED: the SAME forged sender is rejected (550)" "$out_on" "(^|[^0-9])5[0-9][0-9]"
assert_contains "the rejection cites SPF (the claim was checkable, and false)" "$out_on" "[Ss][Pp][Ff]"

# Leave it defended (the sane default).
report_results "Chapter: the mail that lies"
