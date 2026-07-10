#!/usr/bin/env bash
# Phase 1: baseline allow/block filtering. Assumes the stack is up with the baseline policy.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 1: baseline policy (github.com + 1.1.1.1 allowed) [$FILTER_MODE mode] ==="

assert_allowed https://github.com
assert_allowed http://github.com

if [ "$FILTER_MODE" = "https" ]; then
  assert_allowed https://1.1.1.1
  assert_allowed http://1.1.1.1
else
  log "[IP] Skipping IP tests in DNS mode (IPs bypass DNS filtering)"
fi

assert_blocked https://google.com
assert_blocked http://google.com

log "[Log level] Blocked decisions must log at WARN and be alert-flagged"
blocked_line=$($COMPOSE logs g0efilter | strip_ansi | grep -E "WRN.*\.blocked" | grep "action=BLOCKED" || true)
if [ -z "$blocked_line" ]; then
  dump_logs
  fail "no WRN-level blocked log line found (blocked decisions must log at WARN)"
fi
# The genuine block must carry the alert flag in every mode; if a producer stops
# flagging it the notification is silently lost (false negative).
if printf '%s\n' "$blocked_line" | grep -v "alert=true" | grep -q .; then
  dump_logs
  fail "blocked decision is not alert-flagged in $FILTER_MODE mode (missed alert / false negative)"
fi
log "OK: blocked decisions log at WARN and are alert-flagged"

if [ "$FILTER_MODE" = "https" ]; then
  assert_blocked https://1.0.0.1
  assert_blocked http://1.0.0.1
else
  log "[IP] Skipping blocked IP tests in DNS mode"
fi
