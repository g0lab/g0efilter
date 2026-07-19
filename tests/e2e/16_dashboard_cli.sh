#!/usr/bin/env bash
# Black-box coverage for dashboard first-boot credentials, maintenance tasks,
# and recovery through the UI. Commands use the production container entrypoint.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "https" ]; then
  log "Skipping dashboard CLI phase in $FILTER_MODE matrix (runs once, in the https lane)"
  exit 0
fi

log "=== Phase 16: dashboard bootstrap and CLI maintenance tasks ==="

IMAGE="g0efilter-dashboard:e2e"
CLI_CONTAINER="g0efilter-dashboard-cli-$$"
CLI_VOLUME="$CLI_CONTAINER-data"
CLI_ROOT=$(mktemp -d)
BOOTSTRAP_DATA="$CLI_ROOT/bootstrap-data"

mkdir -p "$BOOTSTRAP_DATA"
chmod 0777 "$BOOTSTRAP_DATA"

stop_dashboard() {
  docker rm -f "$CLI_CONTAINER" >/dev/null 2>&1 || true
}

cleanup_cli() {
  status=$?
  if [ "$status" -ne 0 ]; then
    docker logs "$CLI_CONTAINER" 2>&1 || true
  fi
  stop_dashboard
  docker volume rm "$CLI_VOLUME" >/dev/null 2>&1 || true
  rm -rf "$CLI_ROOT"
  exit "$status"
}
trap cleanup_cli EXIT

stack_down
if [ "${E2E_NO_BUILD:-0}" != "1" ]; then
  $COMPOSE build g0efilter-dashboard
fi
docker volume create "$CLI_VOLUME" >/dev/null

start_dashboard() {
  data_dir="$1"
  admin_hash="${2:-}"
  stop_dashboard

  args=(
    --detach
    --name "$CLI_CONTAINER"
    --read-only
    --cap-drop=ALL
    --security-opt=no-new-privileges
    -e PORT=:8081
    -e AUTH_MODE=session
    -e COOKIE_SECURE=false
    -e LOG_LEVEL=INFO
  )
  if [ -n "$data_dir" ]; then
    args+=(-v "$data_dir:/app/data")
  else
    args+=(-e EPHEMERAL=true)
  fi
  if [ -n "$admin_hash" ]; then
    args+=(-e "ADMIN_PASSWORD_HASH=$admin_hash")
  fi

  docker run "${args[@]}" "$IMAGE" >/dev/null
}

cli_curl() {
  docker run --rm --network "container:$CLI_CONTAINER" \
    -v "$CLI_ROOT:/tmp/cli" alpine/curl:latest "$@"
}

wait_dashboard() {
  for i in $(seq 1 30); do
    if cli_curl -sf http://127.0.0.1:8081/health >/dev/null 2>&1; then
      return 0
    fi
    if [ "$i" -eq 30 ]; then
      docker logs "$CLI_CONTAINER" 2>&1 || true
      fail "dashboard CLI test container did not become healthy"
    fi
    sleep 1
  done
}

clean_logs() {
  docker logs "$CLI_CONTAINER" 2>&1 | strip_ansi
}

event_field() {
  event="$1"
  field="$2"
  clean_logs | grep "$event" | sed -n "s/.*${field}=\([^ ]*\).*/\1/p" | tail -1
}

login_code() {
  password="$1"
  cli_curl -s -o /dev/null -w '%{http_code}' -X POST \
    http://127.0.0.1:8081/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -H 'Sec-Fetch-Site: same-origin' \
    -d "{\"username\":\"admin\",\"password\":\"$password\"}"
}

login_session() {
  password="$1"
  cli_curl -sf -c /tmp/cli/cookies -X POST \
    http://127.0.0.1:8081/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -H 'Sec-Fetch-Site: same-origin' \
    -d "{\"username\":\"admin\",\"password\":\"$password\"}" >/dev/null
}

ingest_code() {
  key="$1"
  cli_curl -s -o /dev/null -w '%{http_code}' -X POST \
    http://127.0.0.1:8081/api/v1/logs \
    -H "X-Api-Key: $key" \
    -H 'Content-Type: application/json' \
    -d '{"msg":"dashboard-cli-e2e","action":"ALLOWED"}'
}

log "[hash-password] Hash from stdin configures a working login"
KNOWN_PASSWORD='container-hash-password'
ADMIN_HASH=$(printf '%s\n' "$KNOWN_PASSWORD" | docker run --rm -i "$IMAGE" hash-password)
echo "$ADMIN_HASH" | grep -Eq '^\$2[aby]\$[0-9]{2}\$' \
  || fail "hash-password returned an invalid bcrypt hash: $ADMIN_HASH"

start_dashboard "$CLI_VOLUME" "$ADMIN_HASH"
wait_dashboard
[ "$(login_code "$KNOWN_PASSWORD")" = "200" ] || fail "hash-password output did not configure login"
HASH_BOOTSTRAP_KEY=$(event_field dashboard.api_key_generated key)
echo "$HASH_BOOTSTRAP_KEY" | grep -Eq '^g0e_[0-9a-f]{64}$' \
  || fail "fresh dashboard did not log a generated API key"
[ "$(ingest_code "$HASH_BOOTSTRAP_KEY")" = "201" ] \
  || fail "generated API key did not authenticate ingestion"

docker restart "$CLI_CONTAINER" >/dev/null
wait_dashboard
[ "$(clean_logs | grep -c dashboard.api_key_generated || true)" = "1" ] \
  || fail "generated API key was logged more than once across restart"
[ "$(ingest_code "$HASH_BOOTSTRAP_KEY")" = "201" ] \
  || fail "generated API key did not survive restart"
stop_dashboard
log "OK: hash-password, default database path, and named-volume persistence"

log "[first startup] Generated admin password and API key are usable and logged once"
start_dashboard "$BOOTSTRAP_DATA"
wait_dashboard
ADMIN_PASSWORD=$(event_field dashboard.admin_password_generated password)
BOOTSTRAP_KEY=$(event_field dashboard.api_key_generated key)
echo "$ADMIN_PASSWORD" | grep -Eq '^[A-Za-z0-9_-]{27,}$' \
  || fail "generated admin password missing from first-start log"
echo "$BOOTSTRAP_KEY" | grep -Eq '^g0e_[0-9a-f]{64}$' \
  || fail "generated API key missing from first-start log"
[ "$(login_code "$ADMIN_PASSWORD")" = "200" ] || fail "generated admin password did not authenticate"
[ "$(ingest_code "$BOOTSTRAP_KEY")" = "201" ] || fail "generated API key did not authenticate"

docker restart "$CLI_CONTAINER" >/dev/null
wait_dashboard
[ "$(clean_logs | grep -c dashboard.admin_password_generated || true)" = "1" ] \
  || fail "generated admin password was logged more than once"
[ "$(clean_logs | grep -c dashboard.api_key_generated || true)" = "1" ] \
  || fail "generated API key was logged more than once"
stop_dashboard
log "OK: first-start credentials and restart behavior"

log "[reset-password] Printed replacement works and old password stops working"
RESET_PASSWORD_OUT=$(docker run --rm \
  -v "$BOOTSTRAP_DATA:/app/data" \
  "$IMAGE" reset-password)
RESET_PASSWORD=$(printf '%s\n' "$RESET_PASSWORD_OUT" | tail -1)
echo "$RESET_PASSWORD" | grep -Eq '^[A-Za-z0-9_-]{27,}$' \
  || fail "reset-password did not print a generated password: $RESET_PASSWORD_OUT"

start_dashboard "$BOOTSTRAP_DATA"
wait_dashboard
[ "$(login_code "$ADMIN_PASSWORD")" = "401" ] || fail "old admin password survived reset"
[ "$(login_code "$RESET_PASSWORD")" = "200" ] || fail "reset admin password did not authenticate"
log "OK: reset-password rotation"

log "[no active keys] Dashboard stays up and the UI creates a replacement"
login_session "$RESET_PASSWORD"
KEYS=$(cli_curl -sf -b /tmp/cli/cookies http://127.0.0.1:8081/api/v1/apikeys)
BOOTSTRAP_ID=$(printf '%s\n' "$KEYS" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$BOOTSTRAP_ID" ] || fail "could not find bootstrap API key metadata: $KEYS"
cli_curl -sf -b /tmp/cli/cookies -X DELETE \
  "http://127.0.0.1:8081/api/v1/apikeys/$BOOTSTRAP_ID" \
  -H 'Sec-Fetch-Site: same-origin' -o /dev/null \
  || fail "could not revoke the last active API key"
[ "$(ingest_code "$BOOTSTRAP_KEY")" = "401" ] || fail "revoked API key still authenticated"

docker restart "$CLI_CONTAINER" >/dev/null
wait_dashboard
[ "$(clean_logs | grep -c dashboard.no_active_api_keys || true)" = "1" ] \
  || fail "restart without active API keys did not emit the expected warning"
[ "$(login_code "$RESET_PASSWORD")" = "200" ] \
  || fail "dashboard login was unavailable with no active API keys"

login_session "$RESET_PASSWORD"
CREATED=$(cli_curl -sf -b /tmp/cli/cookies -X POST \
  http://127.0.0.1:8081/api/v1/apikeys \
  -H 'Content-Type: application/json' \
  -H 'Sec-Fetch-Site: same-origin' \
  -d '{"label":"ui-recovery"}')
REPLACEMENT_KEY=$(printf '%s\n' "$CREATED" | grep -o '"key":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "$REPLACEMENT_KEY" | grep -Eq '^g0e_[0-9a-f]{64}$' \
  || fail "dashboard UI did not return a replacement API key: $CREATED"
[ "$(ingest_code "$REPLACEMENT_KEY")" = "201" ] \
  || fail "UI-created replacement API key did not authenticate"
stop_dashboard
log "OK: no-active-key startup and UI recovery"

log "[ephemeral] Explicit in-memory mode resets credentials on restart"
start_dashboard "" "$ADMIN_HASH"
wait_dashboard
EPHEMERAL_KEY=$(event_field dashboard.api_key_generated key)
echo "$EPHEMERAL_KEY" | grep -Eq '^g0e_[0-9a-f]{64}$' \
  || fail "ephemeral dashboard did not generate an API key"

docker restart "$CLI_CONTAINER" >/dev/null
wait_dashboard
EPHEMERAL_REPLACEMENT=$(event_field dashboard.api_key_generated key)
[ "$EPHEMERAL_REPLACEMENT" != "$EPHEMERAL_KEY" ] \
  || fail "ephemeral API key survived restart"
[ "$(ingest_code "$EPHEMERAL_KEY")" = "401" ] \
  || fail "old ephemeral API key authenticated after restart"
[ "$(ingest_code "$EPHEMERAL_REPLACEMENT")" = "201" ] \
  || fail "replacement ephemeral API key did not authenticate"
stop_dashboard
log "OK: explicit ephemeral mode"

log "[errors] Maintenance commands fail clearly without required input"
if OUT=$(docker run --rm -e EPHEMERAL=true "$IMAGE" reset-password 2>&1); then
  fail "reset-password in ephemeral mode unexpectedly succeeded"
fi
echo "$OUT" | grep -q 'reset-password requires persistent storage' \
  || fail "reset-password ephemeral-mode error was unclear: $OUT"

if OUT=$(printf '\n' | docker run --rm -i "$IMAGE" hash-password 2>&1); then
  fail "hash-password with empty stdin unexpectedly succeeded"
fi
echo "$OUT" | grep -q 'empty password on stdin' \
  || fail "hash-password empty-input error was unclear: $OUT"

log "OK: dashboard production-container bootstrap and CLI tasks"
