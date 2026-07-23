#!/usr/bin/env bash
# Shared helpers for g0efilter e2e tests. Source this from each phase script.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/examples/build"
COMPOSE="docker compose -f $BUILD_DIR/docker-compose-build.yaml"
POLICY_FILE="$BUILD_DIR/policy/policy.yaml"
API="http://localhost:8081/api/v1"
API_KEY="${API_KEY:-your-secure-api-key-here}"
FILTER_MODE="${FILTER_MODE:-https}"

log()  { echo "[e2e] $*"; }
fail() { echo "[e2e] ERROR: $*" >&2; exit 1; }

# g0efilter's console logger colorizes output, so a key and value are split by an
# ANSI reset (alert=<ESC>true). Strip escapes before grepping structured fields.
strip_ansi() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

# Baseline for reload detection: phases run as separate processes, so capture the
# current count at source time (0 when the stack isn't up yet).
RELOAD_BASE=$($COMPOSE logs g0efilter 2>/dev/null | grep -c "policy.applied" || true)

run_curl() {
  $COMPOSE exec tester sh -lc "$1"
}

# seed_policy <yaml-content>: overwrite the shared policy file.
# Records the current policy.applied count so wait_for_policy_reload can poll
# for the reload actually landing instead of sleeping a fixed interval.
seed_policy() {
  RELOAD_BASE=$($COMPOSE logs g0efilter 2>/dev/null | grep -c "policy.applied" || true)
  printf '%s\n' "$1" > "$POLICY_FILE"
  chmod 666 "$POLICY_FILE"
}

baseline_policy() {
  seed_policy "---
allowlist:
  ips:
    - '1.1.1.1'
  domains:
    - 'github.com'"
}

# stack_up [extra docker compose env as VAR=val args]
# Builds the image unless E2E_NO_BUILD=1, in which case it expects a pre-loaded
# g0efilter:e2e image (CI builds once and shares it across parallel jobs).
stack_up() {
  local -a build_args=(--build)
  [ "${E2E_NO_BUILD:-0}" = "1" ] && build_args=()
  (cd "$BUILD_DIR" && env FILTER_MODE="$FILTER_MODE" "$@" docker compose -f docker-compose-build.yaml up -d "${build_args[@]}" --force-recreate g0efilter g0efilter-dashboard tester)
  RELOAD_BASE=0 # fresh container, fresh logs
}

stack_down() {
  (cd "$BUILD_DIR" && docker compose -f docker-compose-build.yaml down -v --remove-orphans >/dev/null 2>&1 || true)
}

dump_logs() {
  $COMPOSE logs g0efilter || true
  $COMPOSE logs g0efilter-dashboard || true
}

# nft_contains <family> <table> <pattern> <description>
# Asserts an nft table listing contains a pattern, retrying briefly: a policy
# reload deletes and recreates the tables, so a listing can momentarily miss a set.
nft_contains() {
  local family="$1" table="$2" pattern="$3" desc="$4"
  for _ in $(seq 1 10); do
    if $COMPOSE exec g0efilter nft list table "$family" "$table" 2>/dev/null | grep -q "$pattern"; then
      log "OK: $desc"
      return 0
    fi
    sleep 1
  done
  dump_logs
  fail "$desc (pattern '$pattern' not found in $family $table)"
}

wait_ready() {
  log "Waiting for g0efilter to be ready..."
  sleep 5

  log "Waiting for dashboard health endpoint..."
  for i in $(seq 1 30); do
    if run_curl "curl -sf http://localhost:8081/health" >/dev/null 2>&1; then
      log "Dashboard is ready (attempt $i)"
      return 0
    fi
    [ "$i" -eq 30 ] && { dump_logs; fail "Dashboard did not become healthy in 30s"; }
    sleep 1
  done
}

# assert_allowed <url> [max-time]
# Retries once: right after a policy reload the proxies restart, and in dns modes
# a lookup landing in that window fails without meaning the traffic is blocked.
assert_allowed() {
  local url="$1" t="${2:-10}"
  if run_curl "curl -sS --max-time $t $url -o /dev/null" 2>/dev/null; then
    log "OK: $url allowed"
    return 0
  fi
  sleep 3
  run_curl "curl -sS --max-time $t $url -o /dev/null" \
    || fail "$url was blocked but should be allowed"
  log "OK: $url allowed (after retry)"
}

# assert_blocked <url> [max-time]
assert_blocked() {
  local url="$1" t="${2:-5}"
  if run_curl "curl -sS --max-time $t $url -o /dev/null" 2>/dev/null; then
    fail "$url was allowed but should be blocked"
  fi
  log "OK: $url blocked"
}

# assert_no_dns_block <qname>: fail if g0efilter logged a dns.blocked event for
# qname. Guards against the dual-stack false positive where an unmatched AAAA of
# an IP-allowlisted host was sinkholed and paged.
assert_no_dns_block() {
  local qname="$1" re
  re="qname=${qname//./\\.}( |$)" # exact qname; a search-suffixed variant must not match
  sleep 2                         # let a would-be AAAA block log flush before asserting its absence
  if $COMPOSE logs g0efilter 2>/dev/null | strip_ansi | grep "dns.blocked" | grep -Eq "$re"; then
    dump_logs
    fail "false-positive dns.blocked logged for $qname"
  fi
  log "OK: no dns.blocked logged for $qname"
}

# assert_dns_block_alerts <qname>: fail unless g0efilter logged a dns.blocked
# event for qname carrying alert=true. Guards against a genuine block silently
# losing its notification (false negative) if a producer stops flagging alerts.
assert_dns_block_alerts() {
  local qname="$1" re
  re="qname=${qname//./\\.}( |$)"
  for _ in $(seq 1 10); do
    if $COMPOSE logs g0efilter 2>/dev/null | strip_ansi | grep "dns.blocked" | grep -E "$re" | grep -q "alert=true"; then
      log "OK: dns.blocked for $qname is alert-flagged"
      return 0
    fi
    sleep 1
  done
  dump_logs
  fail "expected an alert-flagged dns.blocked for $qname (missed alert / false negative)"
}

# wait_for_policy_reload: g0efilter polls the policy file every 5s. Waits for a
# new policy.applied log line (seed_policy captured the baseline count), then a
# short settle for the restarted services to start listening.
wait_for_policy_reload() {
  log "Waiting for policy reload..."
  for i in $(seq 1 30); do
    now=$($COMPOSE logs g0efilter 2>/dev/null | grep -c "policy.applied" || true)
    if [ "${now:-0}" -gt "${RELOAD_BASE:-0}" ]; then
      sleep 2
      log "Policy reload applied (after ${i}s)"
      return 0
    fi
    sleep 1
  done
  dump_logs
  fail "policy reload did not apply within 30s"
}

# wait_for_log <query> [timeout]: poll the dashboard logs API until an entry
# matching <query> appears. Log shipping is async, so this replaces a fixed
# post-traffic sleep - it returns as soon as the entry lands.
wait_for_log() {
  local query="$1" timeout="${2:-15}"
  for _ in $(seq 1 "$timeout"); do
    if run_curl "curl -sf '$API/logs?q=$query&limit=100'" 2>/dev/null | grep -q "\"$query\""; then
      return 0
    fi
    sleep 1
  done
  return 1
}
