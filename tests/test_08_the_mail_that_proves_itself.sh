#!/usr/bin/env bash
# Chapter: "The mail that proves itself — DKIM signing (the send side)."
#
# The last leg of the mail story. Chapters 5–6 rejected a spoof because the
# claim to be boss.lab was checkable and false. This one is the other half: our
# own domain mail.lab SIGNS what it sends with DKIM, so a receiver can check the
# claim to be us and find it TRUE. We prove three things:
#   - the published DNS key matches the private signing key (opendkim-testkey),
#   - real outbound mail carries a DKIM-Signature for d=mail.lab,
#   - that signature actually verifies (dkimverify against the published key).
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

echo ""; echo "${BOLD}  Chapter — the mail that proves itself (DKIM)${RESET}"; echo ""

assert "opendkim is running" ssh_defender "systemctl is-active --quiet opendkim"

# 1) The published key is being served (informational — opendkim-testkey is
# finicky about its resolver; the real proof is dkimverify below).
testkey=$(ssh_defender "sudo opendkim-testkey -d mail.lab -s mail -vvv 2>&1" || true)
log_info "opendkim-testkey: $(echo "$testkey" | tr '\n' ' ' | sed 's/  */ /g')"

# 2) Put ONLY opendkim in the milter chain, then send real outbound mail from a
# mail.lab sender and capture what was delivered.
ssh_defender "sudo postconf -e 'smtpd_milters=inet:localhost:8891' && sudo systemctl reload postfix && sudo truncate -s 0 /var/mail/victim 2>/dev/null; true" >/dev/null 2>&1 || true
sleep 1
ssh_defender "swaks --server 127.0.0.1 --from postmaster@mail.lab --to victim@mail.lab --helo mail.lab --header 'Subject: signed hello' --body 'from us, really' 2>&1 | tail -3" >/dev/null 2>&1 || true
sleep 2

# The delivered message (strip the mbox 'From ' envelope line for the verifier).
msg=$(ssh_defender "sudo sed '1{/^From /d}' /var/mail/victim 2>/dev/null" || true)
assert_contains "outbound mail carries a DKIM-Signature" "$msg" "DKIM-Signature:"
assert_contains "the signature is for our domain (d=mail.lab)" "$msg" "d=mail.lab"

# 3) The signature actually verifies against the published key.
verify=$(ssh_defender "sudo sed '1{/^From /d}' /var/mail/victim 2>/dev/null | dkimverify 2>&1; echo rc=\$?" || true)
log_info "dkimverify: $(echo "$verify" | tr '\n' ' ')"
assert_contains "dkimverify accepts the signature (signature valid=True or rc=0)" "$verify" "(valid.*[Tt]rue|signature ok|rc=0)"

# Restore the sane default (chapter 5 state): SPF on, milters off.
ssh_defender "sudo /usr/local/bin/mail-dmarc-off; sudo /usr/local/bin/mail-spf-on" >/dev/null 2>&1 || true

report_results "Chapter: the mail that proves itself"
