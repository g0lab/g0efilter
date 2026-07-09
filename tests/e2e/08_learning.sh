#!/usr/bin/env bash
# Phase 6: learning mode - nothing is blocked, observed domains/IPs are appended to the policy.
# Requires a container recreate (LEARNING_MODE is env-based).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 6: learning mode [$FILTER_MODE mode] ==="

baseline_policy
stack_up LEARNING_MODE=true
wait_ready

log "[Learn] Non-allowlisted domain must pass in learning mode"
assert_allowed https://google.com

if [ "$FILTER_MODE" = "https" ]; then
  log "[Learn] Direct-to-IP (no SNI is sent for IP URLs) must pass and learn the IP"
  assert_allowed https://1.0.0.1
fi

log "[Learn] Waiting for learner flush + policy write..."
sleep 8

grep -q 'google.com' "$POLICY_FILE" || { cat "$POLICY_FILE"; fail "google.com was not learned into policy.yaml"; }
log "OK: google.com learned into policy.yaml"

if [ "$FILTER_MODE" = "https" ]; then
  grep -q '1.0.0.1' "$POLICY_FILE" || { cat "$POLICY_FILE"; fail "1.0.0.1 was not learned into policy.yaml"; }
  log "OK: 1.0.0.1 learned into policy.yaml"
fi

log "[Learn] Learning must not churn the stack: the policy watcher is disabled"
LEARN_LOGS=$($COMPOSE logs g0efilter 2>/dev/null)
grep -q "policy.watcher_disabled" <<< "$LEARN_LOGS" \
  || { dump_logs; fail "expected policy.watcher_disabled in learning mode"; }
if grep -q "policy.applied" <<< "$LEARN_LOGS"; then
  dump_logs; fail "learning mode triggered a policy reload (policy.applied) but should not"
fi
log "OK: no reload churn in learning mode"

log "[Learn] Traffic still passes (learning is non-blocking, no reload needed)"
assert_allowed https://github.com

log "OK: learning mode verified"
