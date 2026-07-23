#!/usr/bin/env bash
# Phase 2: remote unblock via the dashboard API, then live policy reload.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 2: remote unblock google.com [$FILTER_MODE mode] ==="

log "[Unblock] Create request for google.com targeting host-01"
CREATE=$(run_curl "curl -sf -X POST $API/unblocks \
  -H 'Content-Type: application/json' \
  -d '{\"type\":\"domain\",\"value\":\"google.com\",\"target_hostname\":\"host-01\"}'")
echo "$CREATE" | grep -q '"status":"pending"' || fail "create failed: $CREATE"
ID=$(echo "$CREATE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$ID" ] || fail "no id returned"
log "OK: created id=$ID"

log "[Unblock] Status shows google.com in pending with target_hostname"
STATUS=$(run_curl "curl -sf $API/unblocks/status")
echo "$STATUS" | grep -q '"pending"' || fail "no pending array in status response"
echo "$STATUS" | grep -q '"google.com"' || fail "google.com not in status"
echo "$STATUS" | grep -q '"target_hostname":"host-01"' || fail "target_hostname not in pending status"
log "OK: google.com in pending for host-01"

log "[Unblock] Waiting for g0efilter (host-01) to poll and apply unblock..."
for i in $(seq 1 15); do
  STATUS_NOW=$(run_curl "curl -sf $API/unblocks/status")
  if echo "$STATUS_NOW" | grep -q '"pending":\[\]'; then
    log "OK: g0efilter processed unblock (attempt $i)"
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "Status: $STATUS_NOW"
    $COMPOSE logs g0efilter | tail -20
    fail "unblock not completed after 75s"
  fi
  sleep 5
done

log "[Unblock] Verify completed entry preserves target_hostname"
COMPLETED_STATUS=$(run_curl "curl -sf $API/unblocks/status")
echo "$COMPLETED_STATUS" | grep -q '"target_hostname":"host-01"' \
  || fail "target_hostname not preserved in completed: $COMPLETED_STATUS"
log "OK: completed entry has target_hostname=host-01"

log "[Unblock] Verify google.com added to policy.yaml"
grep -Fq -- "- 'google.com'" "$POLICY_FILE" \
  || { cat "$POLICY_FILE"; fail "google.com not in policy.yaml"; }
log "OK: google.com found in policy.yaml"

log "[Unblock] Verify pending list is empty"
PENDING=$(run_curl "curl -sf -H 'X-API-Key: $API_KEY' $API/unblocks")
echo "$PENDING" | grep -q '"pending":\[\]' || fail "pending list not empty: $PENDING"
log "OK: pending list empty"

wait_for_policy_reload

assert_allowed https://google.com
assert_allowed http://google.com

log "[Unblock] Invalid type -> 400"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -X POST $API/unblocks \
  -H 'Content-Type: application/json' \
  -d '{\"type\":\"badtype\",\"value\":\"example.com\"}'")
[ "$CODE" = "400" ] || fail "got $CODE, want 400"
log "OK"

log "[Unblock] Invalid IP -> 400"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -X POST $API/unblocks \
  -H 'Content-Type: application/json' \
  -d '{\"type\":\"ip\",\"value\":\"not-an-ip\"}'")
[ "$CODE" = "400" ] || fail "got $CODE, want 400"
log "OK"

log "[Unblock] Unknown ack ID -> 404"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: $API_KEY' \
  $API/unblocks/ack \
  -d '{\"id\":\"nonexistent-id\"}'")
[ "$CODE" = "404" ] || fail "got $CODE, want 404"
log "OK"

log "[Unblock] Unauthenticated poll -> 401"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' $API/unblocks")
[ "$CODE" = "401" ] || fail "got $CODE, want 401"
log "OK"
