#!/usr/bin/env bash
# Chapter: "The zero has two readings — the blind filter."
#
# A fail2ban counter sitting at zero means either "nobody attacked" or "the
# filter is blind". You cannot tell which by looking. Here we prove the second
# case exists: the SAME log, the SAME events, read by two filters — one that
# matches nothing (because it starts with a date fail2ban already stripped) and
# one that matches everything. The events were always there; the zero was the
# filter's fault. (This is the 2026 VPS incident in miniature: 0 of thousands of
# lines, because the date was in the way.)
set -euo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$TESTS_DIR/_common.sh"

LOG=/opt/cyber-lab/samples/auth-sample.log
BLIND=/etc/fail2ban/filter.d/cyber-blind.conf
GOOD=/etc/fail2ban/filter.d/cyber-good.conf

echo ""; echo "${BOLD}  Chapter — the zero has two readings${RESET}"; echo ""

assert "sample log is present on the defender" ssh_defender "test -s $LOG"
assert "the two filters are present" ssh_defender "test -f $BLIND && test -f $GOOD"

# fail2ban-regex prints a line like: "<N> match(es)" / "Lines: ... <N> matched ..."
# We read the number of matched lines for each filter.
_matched() { ssh_defender "sudo fail2ban-regex '$LOG' '$1' 2>/dev/null | grep -iE 'matched' | tail -1"; }

blind_line=$(_matched "$BLIND")
good_line=$(_matched "$GOOD")
log_info "blind filter: $blind_line"
log_info "good  filter: $good_line"

# The blind filter matches 0 lines despite the log being full of failures.
assert_contains "the BLIND filter matches 0 lines (looks calm, is blind)" "$blind_line" "(^|[^0-9])0 (lines )?matched|0 match"

# The good filter matches every failure line — proof the events were there.
assert_not_contains "the GOOD filter does NOT match zero" "$good_line" "(^|[^0-9])0 (lines )?matched|(^|[^0-9])0 match"
# be explicit: it should report 5 matches for our 5-line sample
assert_contains "the GOOD filter matches all 5 failures" "$good_line" "5"

report_results "Chapter: the zero has two readings"
