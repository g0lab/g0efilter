#!/usr/bin/env bash
# Phase 8: audit (dry-run) enforcement - would-be-blocked traffic passes and is
# logged with the AUDIT action. Recreates the container with ENFORCE=audit.
# Runs in the https lane only (the audit path is mode-independent).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "https" ]; then
  log "Skipping audit phase in $FILTER_MODE matrix (runs once, in the https lane)"
  exit 0
fi

log "=== Phase 8: audit (dry-run) enforcement ==="

baseline_policy
stack_up ENFORCE=audit
wait_ready

log "[Audit] Filter chain must fail open (no policy drop)"
RULESET=$($COMPOSE exec g0efilter nft list table ip g0efilter_v4) \
  || fail "could not list g0efilter_v4 nft table"
if echo "$RULESET" | grep -q "policy drop"; then
  fail "audit mode ruleset still contains policy drop"
fi
log "OK: kernel chains fail open"

log "[Audit] Allowed traffic still works and logs ALLOWED"
assert_allowed https://github.com

log "[Audit] Non-allowlisted domain PASSES in audit mode"
assert_allowed https://google.com

log "[Audit] Non-allowlisted IP PASSES in audit mode"
assert_allowed https://1.0.0.1

log "[Audit] Would-be-blocked traffic is logged with the AUDIT action"
wait_for_log "google.com" 15 || fail "no google.com entries shipped within 15s"
AUDITS=$(run_curl "curl -sf '$API/logs?q=google.com&limit=100'")
echo "$AUDITS" | grep -q '"AUDIT"' \
  || { echo "$AUDITS" | head -c 500; fail "no AUDIT entries for google.com in dashboard"; }
log "OK: google.com logged as AUDIT in dashboard"

log "OK: audit mode verified"
