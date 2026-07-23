#!/usr/bin/env bash
# Phase 2.5: IPv6 remote unblock -> policy reload (https mode only).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "https" ]; then
  log "Skipping IPv6 unblock phase in $FILTER_MODE mode"
  exit 0
fi

log "=== Phase 2.5: remote unblock IPv6 2606:4700:4700::1111 ==="

log "[Unblock] Create request for IPv6 IP 2606:4700:4700::1111"
CREATE=$(run_curl "curl -sf -X POST $API/unblocks \
  -H 'Content-Type: application/json' \
  -d '{\"type\":\"ip\",\"value\":\"2606:4700:4700::1111\",\"target_hostname\":\"host-01\"}'")
echo "$CREATE" | grep -q '"status":"pending"' || fail "create failed: $CREATE"
ID=$(echo "$CREATE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$ID" ] || fail "no id returned"
log "OK: created id=$ID"

log "[Unblock] Waiting for g0efilter to poll and apply IPv6 unblock..."
for i in $(seq 1 15); do
  STATUS_NOW=$(run_curl "curl -sf $API/unblocks/status")
  if echo "$STATUS_NOW" | grep -q '"pending":\[\]'; then
    log "OK: g0efilter processed IPv6 unblock (attempt $i)"
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "Status: $STATUS_NOW"
    $COMPOSE logs g0efilter | tail -20
    fail "IPv6 unblock not completed after 75s"
  fi
  sleep 5
done

log "[Unblock] Verify 2606:4700:4700::1111 added to policy.yaml"
grep -Fq -- "- '2606:4700:4700::1111'" "$POLICY_FILE" \
  || { cat "$POLICY_FILE"; fail "IPv6 address not in policy.yaml"; }
log "OK: 2606:4700:4700::1111 found in policy.yaml"

wait_for_policy_reload

nft_contains ip6 g0efilter_v6 "2606:4700:4700::1111" "2606:4700:4700::1111 in allow_daddr_v6 set"

log "[IPv6] Verify ip6 NAT table created"
$COMPOSE exec g0efilter nft list tables | grep -q "g0efilter_nat_v6" \
  || fail "g0efilter_nat_v6 table not found"
log "OK: g0efilter_nat_v6 table present"

nft_contains ip6 g0efilter_v6 "icmpv6 type echo-request" "v6 filter has icmpv6 echo-request rule"
nft_contains ip6 g0efilter_v6 "ip6 daddr @allow_daddr_v6" "v6 filter has allow rule"

log "[IPv6] Checking for IPv6 default route in tester container..."
if $COMPOSE exec tester sh -lc 'ip -6 route 2>/dev/null | grep -q "^default"'; then
  log "[IPv6] IPv6 default route present - attempting curl -6"
  run_curl "curl -6 -sS --max-time 10 https://[2606:4700:4700::1111] -o /dev/null" \
    || fail "IPv6 route present but curl -6 failed"
  log "OK: IPv6 connection to allowed address succeeded"
else
  log "INFO: no IPv6 default route in tester container (expected on GitHub-hosted runners) - skipping curl -6"
fi
