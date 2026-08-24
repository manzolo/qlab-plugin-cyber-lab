#!/usr/bin/env bash
# Chapter: "Vulnerable PHP — close it, and prove it closed."
#
# The defensive loop this whole collection is about, on a web app:
#   1. the attack works (RCE: the attacker runs a command on the server),
#   2. you harden the app,
#   3. the SAME attack now fails.
# Step 3 is the point. "I added a filter" is not a defense until the attack
# that used to work stops working — measured, from the attacker.
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

WEB="http://$DEFENDER_IP:8080"

echo ""; echo "${BOLD}  Chapter — close it, and prove it closed${RESET}"; echo ""

# Always start from the VULNERABLE state, so the test is idempotent.
ssh_defender "sudo rm -f /etc/cyber-lab/web-hardened; sudo systemctl restart cyber-web" >/dev/null 2>&1 || true
for _i in $(seq 1 8); do
    ssh_attacker "curl -s -o /dev/null $WEB" >/dev/null 2>&1 && break || true
    sleep 2
done

# --- The web app is reachable and admits it is vulnerable ---
home=$(ssh_attacker "curl -s $WEB" || true)
assert_contains "web app reachable from the attacker" "$home" "cyber-lab web"
assert_contains "app is in the VULNERABLE state to begin with" "$home" "VULNERABLE"

# --- Attack #1 (RCE): the attacker runs 'id' ON THE SERVER ---
rce=$(ssh_attacker "curl -s '$WEB/?r=exec&cmd=id'" || true)
assert_contains "RCE works while vulnerable (attacker runs 'id' on the defender)" "$rce" "uid="
# and the classic pair, for good measure
xss=$(ssh_attacker "curl -s '$WEB/?r=echo&msg=<script>x</script>'" || true)
assert_contains "XSS: input reflected unescaped" "$xss" "<script>x</script>"
trav=$(ssh_attacker "curl -s '$WEB/?r=file&name=/etc/passwd'" || true)
assert_contains "path traversal: /etc/passwd leaks" "$trav" "root:.*:0:0:"

# --- Harden (the student's fix), then RESTART so the change takes effect ---
log_info "Hardening the app (touch /etc/cyber-lab/web-hardened; restart cyber-web)..."
ssh_defender "sudo mkdir -p /etc/cyber-lab && sudo touch /etc/cyber-lab/web-hardened && sudo systemctl restart cyber-web" >/dev/null 2>&1 || true
for _i in $(seq 1 8); do
    s=$(ssh_attacker "curl -s $WEB" 2>/dev/null || true)
    echo "$s" | grep -q HARDENED && break; sleep 2
done

# --- Proof: the SAME attacks now fail ---
code=$(ssh_attacker "curl -s -o /dev/null -w '%{http_code}' '$WEB/?r=exec&cmd=id'" || true)
assert_contains "after hardening, RCE is refused (HTTP 403)" "$code" "403"
rce2=$(ssh_attacker "curl -s '$WEB/?r=exec&cmd=id'" || true)
assert_not_contains "after hardening, no command output leaks" "$rce2" "uid="
xss2=$(ssh_attacker "curl -s '$WEB/?r=echo&msg=<script>x</script>'" || true)
assert_not_contains "after hardening, XSS payload is escaped" "$xss2" "<script>x</script>"
code_t=$(ssh_attacker "curl -s -o /dev/null -w '%{http_code}' '$WEB/?r=file&name=/etc/passwd'" || true)
assert_contains "after hardening, traversal is refused (HTTP 403)" "$code_t" "403"

# Leave the app back in the vulnerable state for the next reader / re-run.
ssh_defender "sudo rm -f /etc/cyber-lab/web-hardened; sudo systemctl restart cyber-web" >/dev/null 2>&1 || true

report_results "Chapter: close it, and prove it closed"
