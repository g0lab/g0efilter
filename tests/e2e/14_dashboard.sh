#!/usr/bin/env bash
# Dedicated dashboard control-plane coverage. Runs the production container
# with session auth and SQLite instead of the lightweight AUTH_MODE=none setup
# used by the traffic-focused phases.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "https" ]; then
  log "Skipping dashboard phase in $FILTER_MODE matrix (runs once, in the https lane)"
  exit 0
fi

log "=== Phase 14: dashboard auth, persistence, API keys, fleet, and SSE ==="

ADMIN_PASSWORD='e2e-password'
# bcrypt for ADMIN_PASSWORD above. This is an intentionally public test-only credential.
ADMIN_HASH='$2a$10$0AQE1U75HW8UmpeVt5sWBeH73zpoPC6pTZ3ZBUHiuvInqYLmOTEx6'
COOKIE_JAR=/tmp/g0efilter-dashboard.cookies

baseline_policy
stack_up \
  DASHBOARD_AUTH_MODE=session \
  DASHBOARD_ADMIN_PASSWORD_HASH="$ADMIN_HASH" \
  DASHBOARD_COOKIE_SECURE=false \
  DASHBOARD_DB_PATH=/app/data/dashboard.db \
  DASHBOARD_FLEET_ENABLED=true \
  DASHBOARD_CORS_ALLOWED_ORIGINS=https://ui.example
wait_ready

log "[Public] Health, login page, static asset, and security headers"
HEALTH_HEADERS=$(run_curl "curl -sS -D - -o /dev/null http://localhost:8081/health")
echo "$HEALTH_HEADERS" | grep -qi '^Content-Security-Policy:' || fail "health missing CSP"
echo "$HEALTH_HEADERS" | grep -qi '^X-Content-Type-Options: nosniff' || fail "health missing nosniff"
echo "$HEALTH_HEADERS" | grep -qi '^X-Request-ID:' || fail "health missing request ID"
LOGIN_HTML=$(run_curl "curl -sf http://localhost:8081/login.html")
echo "$LOGIN_HTML" | grep -q 'g0efilter dashboard - login' || fail "login page not served"
ASSET=$(echo "$LOGIN_HTML" | grep -o '/assets/[^" ]*\.js' | head -1)
[ -n "$ASSET" ] || fail "login page has no JavaScript asset"
run_curl "curl -sf http://localhost:8081$ASSET -o /dev/null" || fail "login asset not public"
log "OK: public surface and global headers"

log "[Auth] Unauthenticated API is denied and browser page redirects"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' $API/logs")
[ "$CODE" = "401" ] || fail "unauthenticated logs returned $CODE, want 401"
REDIRECT=$(run_curl "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Accept: text/html' http://localhost:8081/")
echo "$REDIRECT" | grep -q '^302 http://localhost:8081/login.html$' \
  || fail "unauthenticated UI did not redirect: $REDIRECT"
log "OK: unauthenticated requests denied"

log "[CORS] Allowed preflight is answered before authentication"
CORS_HEADERS=$(run_curl "curl -sS -D - -o /dev/null -X OPTIONS $API/logs \
  -H 'Origin: https://ui.example' \
  -H 'Access-Control-Request-Method: GET'")
echo "$CORS_HEADERS" | grep -qi '^Access-Control-Allow-Origin: https://ui.example' \
  || fail "allowed CORS origin not returned"
echo "$CORS_HEADERS" | grep -qi '^Access-Control-Allow-Credentials: true' \
  || fail "credentialed CORS header missing"
log "OK: CORS preflight"

log "[Auth] Invalid login is rejected; valid login mints a secure session"
BAD_CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -X POST $API/auth/login \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-origin' \
  -d '{\"username\":\"admin\",\"password\":\"wrong\"}'")
[ "$BAD_CODE" = "401" ] || fail "bad login returned $BAD_CODE, want 401"
LOGIN=$(run_curl "curl -sf -c $COOKIE_JAR -X POST $API/auth/login \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-origin' \
  -d '{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}'")
echo "$LOGIN" | grep -q '"username":"admin"' || fail "valid login failed: $LOGIN"
ME=$(run_curl "curl -sf -b $COOKIE_JAR $API/auth/me")
echo "$ME" | grep -q '"username":"admin"' || fail "session did not authenticate: $ME"
run_curl "curl -sf -b $COOKIE_JAR http://localhost:8081/ -o /dev/null" \
  || fail "authenticated UI was not served"
log "OK: session login and authenticated UI"

log "[CSRF] Cross-site admin mutation is rejected"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -b $COOKIE_JAR -X POST $API/apikeys \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: cross-site' \
  -d '{\"label\":\"csrf-must-fail\"}'")
[ "$CODE" = "403" ] || fail "cross-site mutation returned $CODE, want 403"
log "OK: CSRF rejection"

log "[API keys] Create a persistent machine key through an authenticated route"
CREATED=$(run_curl "curl -sf -b $COOKIE_JAR -X POST $API/apikeys \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-origin' \
  -d '{\"label\":\"e2e-agent\"}'")
MACHINE_KEY=$(echo "$CREATED" | grep -o '"key":"[^"]*"' | head -1 | cut -d'"' -f4)
KEY_ID=$(echo "$CREATED" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$MACHINE_KEY" ] && [ -n "$KEY_ID" ] || fail "key creation response incomplete: $CREATED"

log "[Logs] New key ingests JSON; wrong content type is rejected"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -X POST $API/logs \
  -H 'X-Api-Key: $MACHINE_KEY' -H 'Content-Type: text/plain' -d '{}'")
[ "$CODE" = "415" ] || fail "wrong content type returned $CODE, want 415"
INGEST=$(run_curl "curl -sf -X POST $API/logs \
  -H 'X-Api-Key: $MACHINE_KEY' -H 'Content-Type: application/json' \
  -d '{\"msg\":\"dashboard-e2e\",\"action\":\"BLOCKED\",\"hostname\":\"e2e-agent\"}'")
echo "$INGEST" | grep -q '"created":1' || fail "log ingestion failed: $INGEST"
LOGS=$(run_curl "curl -sf -b $COOKIE_JAR '$API/logs?q=dashboard-e2e'")
echo "$LOGS" | grep -q 'dashboard-e2e' || fail "persisted log not queryable: $LOGS"
log "OK: API key and persistent log ingestion"

log "[SSE] Authenticated stream connects and emits its initial frame"
SSE=$(run_curl "curl -sN --max-time 2 -b $COOKIE_JAR $API/events || true")
echo "$SSE" | grep -q ': connected' || fail "SSE did not emit connected frame"
log "OK: SSE connected"

log "[Fleet] Reconcile instance, assign group policy, and receive desired state"
SYNC=$(run_curl "curl -sf -X POST $API/sync \
  -H 'X-Api-Key: $MACHINE_KEY' -H 'Content-Type: application/json' \
  -d '{\"hostname\":\"e2e-agent\",\"version\":\"e2e\",\"filter_mode\":\"https\",\"config_hash\":\"\"}'")
echo "$SYNC" | grep -q '"managed":false' || fail "initial fleet sync should be unmanaged: $SYNC"
INSTANCES=$(run_curl "curl -sf -b $COOKIE_JAR $API/fleet/instances")
INSTANCE_ID=$(echo "$INSTANCES" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$INSTANCE_ID" ] || fail "fleet instance not recorded: $INSTANCES"
GROUP=$(run_curl "curl -sf -b $COOKIE_JAR -X POST $API/fleet/groups \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-origin' \
  -d '{\"name\":\"e2e-group\"}'")
GROUP_ID=$(echo "$GROUP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$GROUP_ID" ] || fail "fleet group not created: $GROUP"
run_curl "curl -sf -b $COOKIE_JAR -X PUT $API/fleet/groups/$GROUP_ID/policy \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-origin' \
  -d '{\"policy\":\"allowlist: {}\",\"filter_mode\":\"https\"}' -o /dev/null" \
  || fail "group policy update failed"
run_curl "curl -sf -b $COOKIE_JAR -X PUT $API/fleet/instances/$INSTANCE_ID/group \
  -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-origin' \
  -d '{\"group_id\":\"$GROUP_ID\"}' -o /dev/null" || fail "instance assignment failed"
SYNC=$(run_curl "curl -sf -X POST $API/sync \
  -H 'X-Api-Key: $MACHINE_KEY' -H 'Content-Type: application/json' \
  -d '{\"hostname\":\"e2e-agent\",\"version\":\"e2e\",\"filter_mode\":\"https\",\"config_hash\":\"\"}'")
echo "$SYNC" | grep -q '"managed":true' || fail "managed fleet sync failed: $SYNC"
echo "$SYNC" | grep -q '"policy":"allowlist: {}"' || fail "desired policy missing: $SYNC"
log "OK: fleet route parameters and desired-state resolution"

log "[Persistence] Restart dashboard; session, key, logs, and fleet state survive"
$COMPOSE restart g0efilter-dashboard >/dev/null
for i in $(seq 1 30); do
  if run_curl "curl -sf http://localhost:8081/health" >/dev/null 2>&1; then
    break
  fi
  [ "$i" -eq 30 ] && { dump_logs; fail "dashboard did not recover after restart"; }
  sleep 1
done
ME=$(run_curl "curl -sf -b $COOKIE_JAR $API/auth/me")
echo "$ME" | grep -q '"username":"admin"' || fail "session did not survive restart"
run_curl "curl -sf -X POST $API/logs -H 'X-Api-Key: $MACHINE_KEY' \
  -H 'Content-Type: application/json' -d '{\"msg\":\"after-restart\",\"action\":\"ALLOWED\"}' -o /dev/null" \
  || fail "API key did not survive restart"
LOGS=$(run_curl "curl -sf -b $COOKIE_JAR '$API/logs?q=dashboard-e2e'")
echo "$LOGS" | grep -q 'dashboard-e2e' || fail "log did not survive restart"
FLEET_GROUPS=$(run_curl "curl -sf -b $COOKIE_JAR $API/fleet/groups")
grep -q 'e2e-group' <<<"$FLEET_GROUPS" \
  || fail "fleet group did not survive restart: $FLEET_GROUPS"
log "OK: SQLite migration and restart persistence"

if [ "${E2E_BROWSER:-0}" = "1" ]; then
  log "[Browser] Run the Chromium dashboard smoke test"
  (
    cd "$REPO_ROOT/internal/dashboard/ui"
    DASHBOARD_E2E_BASE_URL=http://127.0.0.1:8081 \
      DASHBOARD_E2E_API_KEY="$API_KEY" \
      DASHBOARD_E2E_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
      pnpm test:e2e
  ) || fail "dashboard browser E2E failed"
  log "OK: browser rendered Stream, Aggregates, API Keys, Fleet, SSE, and logout without errors"
else
  log "Skipping browser smoke (set E2E_BROWSER=1; CI/nightly enables it)"
fi

log "[API keys] Revoke the generated key and verify machine access is denied"
run_curl "curl -sf -b $COOKIE_JAR -X DELETE $API/apikeys/$KEY_ID \
  -H 'Sec-Fetch-Site: same-origin' -o /dev/null" || fail "key revocation failed"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -X POST $API/logs \
  -H 'X-Api-Key: $MACHINE_KEY' -H 'Content-Type: application/json' -d '{}'")
[ "$CODE" = "401" ] || fail "revoked API key returned $CODE, want 401"
log "OK: API key revocation"

log "[Auth] Logout revokes the session"
run_curl "curl -sf -b $COOKIE_JAR -c $COOKIE_JAR -X POST $API/auth/logout \
  -H 'Sec-Fetch-Site: same-origin' -o /dev/null" || fail "logout failed"
CODE=$(run_curl "curl -s -o /dev/null -w '%{http_code}' -b $COOKIE_JAR $API/logs")
[ "$CODE" = "401" ] || fail "logged-out session returned $CODE, want 401"
log "OK: dashboard E2E scenario passed"
