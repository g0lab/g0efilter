#!/usr/bin/env bash
# Phase 3: dashboard log ingestion end-to-end (traffic from earlier phases must be visible).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 3: dashboard log verification ==="

log "Waiting for log shipping to complete..."
wait_for_log "google.com" 15 || fail "log shipping did not complete (no google.com entry within 15s)"

log "[Logs] Retrieve all entries"
LOGS=$(run_curl "curl -sf $API/logs?limit=500")
TOTAL=$(echo "$LOGS" | grep -o '"id"' | wc -l)
[ "$TOTAL" -gt 0 ] || fail "dashboard has 0 logs"
log "OK: $TOTAL log entries shipped"

log "[Logs] github.com traffic logged as ALLOWED"
GITHUB=$(run_curl "curl -sf '$API/logs?q=github.com&limit=100'")
echo "$GITHUB" | grep -q '"github.com"' || fail "no github.com entries"
echo "$GITHUB" | grep -q '"ALLOWED"' || fail "github.com not marked ALLOWED"
log "OK: github.com logged as ALLOWED"

log "[Logs] google.com traffic logged as BLOCKED"
GOOGLE=$(run_curl "curl -sf '$API/logs?q=google.com&limit=100'")
echo "$GOOGLE" | grep -q '"google.com"' || fail "no google.com entries"
echo "$GOOGLE" | grep -q '"BLOCKED"' || fail "google.com not marked BLOCKED"
log "OK: google.com logged as BLOCKED"

log "[Logs] Payload fields on a log entry"
echo "$LOGS" | grep -q '"action"' || fail "missing action"
echo "$LOGS" | grep -q '"source_ip"' || fail "missing source_ip"
echo "$LOGS" | grep -q '"flow_id"' || fail "missing flow_id"
echo "$LOGS" | grep -qE '"protocol":"(TCP|UDP)"' || fail "missing concrete protocol value (TCP/UDP)"
log "OK: action, source_ip, flow_id, protocol (TCP/UDP) present"
