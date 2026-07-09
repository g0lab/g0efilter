#!/usr/bin/env bash
# Phase 7: dns-strict mode - connection-time enforcement via kernel timeout sets.
# Unlike plain dns mode, connections to IPs never resolved through the proxy are dropped.
# Recreates the container with FILTER_MODE=dns-strict; runs in the dns CI matrix only.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "dns" ]; then
  log "Skipping dns-strict phase in $FILTER_MODE matrix (runs once, in the dns lane)"
  exit 0
fi

log "=== Phase 7: dns-strict connection-time enforcement ==="

baseline_policy
stack_up FILTER_MODE=dns-strict
wait_ready

nft_contains ip g0efilter_v4 "policy drop" "dns-strict v4 chain is policy drop"
nft_contains ip g0efilter_v4 "resolved_allow_v4" "resolved_allow_v4 set present"
nft_contains ip6 g0efilter_v6 "resolved_allow_v6" "resolved_allow_v6 set present"

log "[Strict] Allowed domain resolves and connects"
assert_allowed https://github.com

log "[Strict] Resolved IPs were pushed into the kernel set with a timeout"
$COMPOSE exec g0efilter nft list set ip g0efilter_v4 resolved_allow_v4 | grep -q "timeout" \
  || fail "resolved_allow_v4 has no timeout entries after an allowed resolution"
log "OK: resolved_allow_v4 populated"

log "[Strict] Blocked domain is sinkholed at DNS"
assert_blocked https://google.com

log "[Strict] Hardcoded IP never resolved through the proxy must be DROPPED"
# This is the enforcement gap vs plain dns mode: there this connection would succeed.
assert_blocked https://1.0.0.1

log "[Strict] Statically allow-listed IP still connects"
assert_allowed https://1.1.1.1

log "[Strict] Second lookup of the allowed domain still works (set refresh path)"
run_curl "curl -sS --max-time 10 -H 'Cache-Control: no-cache' https://github.com -o /dev/null" \
  || fail "repeat request to allowed domain failed"
log "OK: repeat resolution/connection works"

log "[Strict] QUIC (UDP/443) is gated by destination IP, not intercepted"
# dns-strict accepts/drops by destination IP regardless of L4 protocol, so QUIC to an
# allow-listed IP is permitted and QUIC to a never-resolved IP is dropped. curl has no
# HTTP/3, so probe with a raw UDP/443 datagram and read the verdict off the nflog stream.
run_curl "for i in 1 2 3; do echo quic | nc -u -w1 1.1.1.1 443 >/dev/null 2>&1 || true; done"   # allow-listed
run_curl "for i in 1 2 3; do echo quic | nc -u -w1 1.0.0.2 443 >/dev/null 2>&1 || true; done"   # never resolved

# quic_verdict <ip> <action>: true if the nflog stream shows a UDP <action> for <ip>.
# Strip ANSI from the console logs; grep -c (not -q) consumes the whole stream, else
# the early-close SIGPIPE on `docker compose logs` trips pipefail.
quic_verdict() {
  local n
  n=$($COMPOSE logs g0efilter 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | grep "destination_ip=$1 " | grep "protocol=UDP" | grep -c "action=$2 ") || true
  [ "${n:-0}" -gt 0 ]
}

for _ in $(seq 1 10); do
  quic_verdict 1.1.1.1 ALLOWED && quic_verdict 1.0.0.2 BLOCKED && break
  sleep 1
done

quic_verdict 1.1.1.1 ALLOWED || { dump_logs; fail "QUIC (UDP/443) to allow-listed 1.1.1.1 was not accepted"; }
log "OK: QUIC to allow-listed IP accepted (no interception)"
quic_verdict 1.0.0.2 BLOCKED || { dump_logs; fail "QUIC (UDP/443) to non-resolved 1.0.0.2 was not dropped"; }
log "OK: QUIC to non-resolved IP dropped (no egress bypass)"

log "OK: dns-strict mode verified"
