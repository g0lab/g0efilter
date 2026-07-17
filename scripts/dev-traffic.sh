#!/usr/bin/env bash
# Synthetic dashboard traffic for local dev:
#   scripts/dev-traffic.sh [interval-seconds]
# POSTs realistic log events through the real ingest path (API key auth) so
# the live stream, filters, aggregates and unblock buttons have moving data
# across multiple hosts and filter modes.
set -euo pipefail

API="${DASHBOARD_URL:-http://localhost:8081}/api/v1/logs"
KEY="${DEV_API_KEY:-dev-api-key}"
INTERVAL="${1:-2}"

HOSTS=(build-runner-1 build-runner-2 ci-agent)
DOMAINS=(github.com registry.npmjs.org example.com evil.example telemetry.bad.example)
ACTIONS=(ALLOWED ALLOWED ALLOWED BLOCKED AUDIT)
COMPONENTS=(https dns http nflog)

echo ">>> posting to $API every ${INTERVAL}s (ctrl-c to stop)"

i=0
while true; do
  host="${HOSTS[$((RANDOM % ${#HOSTS[@]}))]}"
  domain="${DOMAINS[$((RANDOM % ${#DOMAINS[@]}))]}"
  action="${ACTIONS[$((RANDOM % ${#ACTIONS[@]}))]}"
  component="${COMPONENTS[$((RANDOM % ${#COMPONENTS[@]}))]}"
  dport=443
  if [ "$component" = "dns" ]; then dport=53; fi
  i=$((i + 1))

  body=$(cat <<EOF
{
  "time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "msg": "flow.decision",
  "action": "$action",
  "component": "$component",
  "http_host": "$domain",
  "source_ip": "172.20.0.$((RANDOM % 250 + 2))",
  "source_port": $((RANDOM % 40000 + 1024)),
  "destination_ip": "140.82.$((RANDOM % 250)).$((RANDOM % 250))",
  "destination_port": $dport,
  "hostname": "$host",
  "flow_id": "dev-$i",
  "version": "dev"
}
EOF
)

  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' \
    -d "$body" "$API") || code="000"

  if [ "$code" != "201" ]; then
    echo "!!! ingest returned $code (dashboard down or wrong DEV_API_KEY?)"
  fi

  sleep "$INTERVAL"
done
