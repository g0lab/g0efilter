#!/usr/bin/env bash
# Phase 12: load/stress through the filter.
# Scale knobs: LOAD_TOTAL, LOAD_TOTAL_HTTP, LOAD_CONCURRENCY, LOAD_ALLOWED.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TOTAL="${LOAD_TOTAL:-500}"
TOTAL_HTTP="${LOAD_TOTAL_HTTP:-$((TOTAL / 2))}"
CONCURRENCY="${LOAD_CONCURRENCY:-50}"
ALLOWED_UNDER_LOAD="${LOAD_ALLOWED:-25}"
MAX_TIME="${LOAD_MAX_TIME:-8}"
MAX_LATENCY_MS="${LOAD_MAX_LATENCY_MS:-2000}"
MIN_ALLOWED_PCT="${LOAD_MIN_ALLOWED_PCT:-85}"
MAX_MEMORY_MIB="${LOAD_MAX_MEMORY_MIB:-384}"

BLOCKED_URL="${LOAD_BLOCKED_URL:-https://example.com}"
BLOCKED_URL_HTTP="${LOAD_BLOCKED_URL_HTTP:-http://example.com}"
ALLOWED_URL="${LOAD_ALLOWED_URL:-https://github.com}"
BLOCKED_HOST=$(printf '%s' "$BLOCKED_URL" | sed -E 's|^[a-z]+://||; s|[:/].*||')

# Escape hatch for hosts whose DNS source-port sysctls overlap 61000-64999.
DNS_LEAK_TOLERANCE_PCT="${LOAD_DNS_LEAK_TOLERANCE_PCT:-0}"

log "=== Phase 12: load/stress [$FILTER_MODE mode] ==="
log "total=$TOTAL http=$TOTAL_HTTP concurrency=$CONCURRENCY allowed=$ALLOWED_UNDER_LOAD"

# Marker domain forces a fresh policy.applied event.
seed_policy '---
allowlist:
  ips:
    - "1.1.1.1"
  domains:
    - "github.com"
    - "g0efilter-load-marker.invalid"'
wait_for_policy_reload

run_tester() {
  local script="$1"; shift
  $COMPOSE exec -T tester sh -s "$@" <<SH
$script
SH
}

SUMMARY_ROWS=""
add_row() { SUMMARY_ROWS="${SUMMARY_ROWS}| $1 | $2 | $3 |"$'\n'; }

blast='
total=$1; conc=$2; maxt=$3; url=$4
leaks=0; done=0
while [ $done -lt $total ]; do
  n=$conc
  [ $((done + n)) -gt $total ] && n=$((total - done))
  rm -f /tmp/leak.* 2>/dev/null
  i=0
  while [ $i -lt $n ]; do
    ( curl -sS --max-time $maxt "$url" -o /dev/null 2>/dev/null && : > /tmp/leak.$i ) &
    i=$((i + 1))
  done
  wait
  c=$(ls /tmp/leak.* 2>/dev/null | wc -l)
  leaks=$((leaks + c))
  done=$((done + n))
done
echo "LEAKS=$leaks"
'

blocked_wave() {
  local label="$1" total="$2" url="$3" start end out leaks elapsed_ms rate

  log "[$label] Firing $total blocked connections at $url ($CONCURRENCY at a time)"
  start=$(date +%s%N)
  out=$(run_tester "$blast" "$total" "$CONCURRENCY" "$MAX_TIME" "$url") \
    || fail "[$label] load generator failed to run"
  end=$(date +%s%N)

  leaks=$(printf '%s\n' "$out" | sed -n 's/^LEAKS=//p')
  [ -n "$leaks" ] || fail "[$label] could not read leak count from load run"

  elapsed_ms=$(((end - start) / 1000000))
  [ "$elapsed_ms" -gt 0 ] || elapsed_ms=1
  rate=$((total * 1000 / elapsed_ms))
  log "[$label] $total blocked attempts in ${elapsed_ms}ms (~${rate}/s), leaks=$leaks"
  add_row "$label blocked ($url)" "$total in ${elapsed_ms}ms (~${rate}/s)" "leaks=$leaks"

  if [ "$leaks" -eq 0 ]; then
    log "OK: [$label] no blocked connection leaked"
  elif [ "$FILTER_MODE" = "dns" ] && [ "$DNS_LEAK_TOLERANCE_PCT" -gt 0 ] \
    && [ $((leaks * 100)) -le $((total * DNS_LEAK_TOLERANCE_PCT)) ]; then
    log "WARN: [$label] $leaks/$total leaked via conntrack-tuple collision (within the ${DNS_LEAK_TOLERANCE_PCT}% tolerance opted into via LOAD_DNS_LEAK_TOLERANCE_PCT)"
  else
    fail "[$label] $leaks/$total blocked connections leaked under load"
  fi
}

# L1: mass concurrent blocking - HTTPS (SNI path) and HTTP (Host path).
blocked_wave "L1-https" "$TOTAL" "$BLOCKED_URL"
blocked_wave "L1-http" "$TOTAL_HTTP" "$BLOCKED_URL_HTTP"

# L2: allowed traffic must still flow while blocking load runs.
L2_BLOCKED="$CONCURRENCY"
if [ "$FILTER_MODE" = "dns" ]; then
  allowed_blocked=$($COMPOSE logs g0efilter 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' \
    | grep "dns.allowed" | grep -c "qname=$BLOCKED_HOST" || true)
  [ "${allowed_blocked:-0}" -eq 0 ] \
    || fail "DNS proxy ALLOWED $allowed_blocked queries for $BLOCKED_HOST - filter decision error"
  log "OK: proxy decision log clean - 0 allowed decisions for $BLOCKED_HOST"
  add_row "L1 dns decisions" "0 allowed for $BLOCKED_HOST" "decision layer clean"
fi

if [ "$FILTER_MODE" = "dns" ]; then
  rl=$($COMPOSE logs g0efilter 2>/dev/null | grep -c "dns.rate_limited" || true)
  log "[L1] dns rate limiter engaged on $rl queries during flood"
  add_row "L1 dns rate-limit" "engaged on $rl queries" "informational"

  L2_BLOCKED=15
  log "[L2] dns mode: waiting for the rate-limit bucket to refill"
  sleep 4
fi

log "[L2] $ALLOWED_UNDER_LOAD allowed requests concurrent with $L2_BLOCKED blocked"

mixed='
allowed=$1; blocked=$2; maxt=$3; aurl=$4; burl=$5
rm -f /tmp/ok.* /tmp/leak.* 2>/dev/null
i=0
while [ $i -lt $blocked ]; do
  ( curl -sS --max-time $maxt "$burl" -o /dev/null 2>/dev/null && : > /tmp/leak.$i ) &
  i=$((i + 1))
done
i=0
while [ $i -lt $allowed ]; do
  ( curl -sS --max-time $maxt "$aurl" -o /dev/null 2>/dev/null && : > /tmp/ok.$i ) &
  i=$((i + 1))
done
wait
echo "OK=$(ls /tmp/ok.* 2>/dev/null | wc -l)"
echo "LEAKS=$(ls /tmp/leak.* 2>/dev/null | wc -l)"
'

out=$(run_tester "$mixed" "$ALLOWED_UNDER_LOAD" "$L2_BLOCKED" "$MAX_TIME" "$ALLOWED_URL" "$BLOCKED_URL") \
  || fail "mixed load generator failed to run"

ok=$(printf '%s\n' "$out" | sed -n 's/^OK=//p')
leaks=$(printf '%s\n' "$out" | sed -n 's/^LEAKS=//p')
[ "$ALLOWED_UNDER_LOAD" -gt 0 ] || fail "LOAD_ALLOWED must be greater than 0"
allowed_pct=$((ok * 100 / ALLOWED_UNDER_LOAD))
log "[L2] allowed ok=$ok/$ALLOWED_UNDER_LOAD (${allowed_pct}%), blocked leaks=$leaks"
add_row "L2 mixed" "allowed $ok/$ALLOWED_UNDER_LOAD (${allowed_pct}%)" "leaks=$leaks"

[ "$leaks" -eq 0 ] || fail "$leaks blocked connections leaked during mixed load"
[ "$allowed_pct" -ge "$MIN_ALLOWED_PCT" ] \
  || fail "allowed success ${allowed_pct}% under load, below ${MIN_ALLOWED_PCT}%"
log "OK: allowed traffic survived concurrent blocking load"

# L3: block-decision latency stays bounded (median gates; p95/max informational).
log "[L3] Sampling blocked-decision latency"

latency='
maxt=$1; url=$2
i=0
while [ $i -lt 20 ]; do
  curl -sS -o /dev/null -w "%{time_total}\n" --max-time $maxt "$url" 2>/dev/null || true
  i=$((i + 1))
done
'

samples=$(run_tester "$latency" "$MAX_TIME" "$BLOCKED_URL") || fail "latency sampler failed"
stats=$(printf '%s\n' "$samples" | grep -E '^[0-9.]+$' | sort -n | awk '
  {a[NR]=$1}
  END{
    if(NR==0){print "-1 -1 -1"; exit}
    m=(NR%2)?a[(NR+1)/2]:(a[int(NR/2)]+a[int(NR/2)+1])/2
    p=a[int(NR*0.95)==0?1:int(NR*0.95)]
    printf "%d %d %d", m*1000, p*1000, a[NR]*1000
  }')
read -r median_ms p95_ms max_ms <<< "$stats"

[ "$median_ms" -ge 0 ] || fail "no latency samples collected"
log "[L3] blocked-decision latency median=${median_ms}ms p95=${p95_ms}ms max=${max_ms}ms (median limit ${MAX_LATENCY_MS}ms)"
add_row "L3 latency" "median=${median_ms}ms p95=${p95_ms}ms max=${max_ms}ms" "limit ${MAX_LATENCY_MS}ms"
[ "$median_ms" -le "$MAX_LATENCY_MS" ] \
  || fail "median blocked-decision latency ${median_ms}ms exceeds ${MAX_LATENCY_MS}ms"
log "OK: block-decision latency within bound"

# L4: the filter stayed up and bounded through the load.
log "[L4] Checking filter stability after load"

cid=$($COMPOSE ps -q g0efilter) || true
[ -n "$cid" ] || fail "g0efilter container not found"

running=$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null || echo "unknown")
restarts=$(docker inspect -f '{{.RestartCount}}' "$cid" 2>/dev/null || echo "-1")
[ "$running" = "true" ] || fail "g0efilter is not running after load (state=$running)"
[ "$restarts" = "0" ] || fail "g0efilter restarted $restarts time(s) under load"

mem_bytes=$($COMPOSE exec -T g0efilter sh -lc '
  if [ -r /sys/fs/cgroup/memory.current ]; then cat /sys/fs/cgroup/memory.current
  elif [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then cat /sys/fs/cgroup/memory/memory.usage_in_bytes
  else echo 0; fi' 2>/dev/null | tr -dc '0-9')
mem_mib=$(( (${mem_bytes:-0} + 1048575) / 1048576 ))
log "[L4] running=$running restarts=$restarts memory=${mem_mib}MiB (limit ${MAX_MEMORY_MIB}MiB)"
add_row "L4 stability" "restarts=$restarts memory=${mem_mib}MiB" "limit ${MAX_MEMORY_MIB}MiB"
[ "$mem_mib" -le "$MAX_MEMORY_MIB" ] || fail "memory ${mem_mib}MiB exceeds ${MAX_MEMORY_MIB}MiB after load"

TOTAL_CONNS=$((TOTAL + TOTAL_HTTP + L2_BLOCKED + ALLOWED_UNDER_LOAD))
log "OK: filter stable after $TOTAL_CONNS connections"

# Publish results to the job summary when running in Actions.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Load test ($FILTER_MODE mode) - $TOTAL_CONNS connections"
    echo ""
    echo "| Check | Result | Detail |"
    echo "|---|---|---|"
    printf '%s' "$SUMMARY_ROWS"
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
fi

log "=== Phase 12: all load assertions passed [$FILTER_MODE mode] ==="
