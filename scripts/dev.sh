#!/usr/bin/env bash
# One-command local dev: runs the dashboard API (:8081) and the Vite UI dev
# server (:5000, /api proxied to the backend) together, with a single ctrl-c
# tearing both down.
#
#   scripts/dev.sh              # API + UI, seeded with 10,000 historical events
#   scripts/dev.sh --traffic    # also stream synthetic log/traffic data
#   DEV_SEED_COUNT=0 scripts/dev.sh  # skip seeding
#
# UI:  http://localhost:5000   (HMR)
# API: http://localhost:8081   (embedded UI also served here)
set -euo pipefail
export GOEXPERIMENT=jsonv2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TRAFFIC=false
if [ "${1:-}" = "--traffic" ]; then
  TRAFFIC=true
fi

UI_DIR="$ROOT/dashboard/ui"

if [ ! -d "$UI_DIR/node_modules" ]; then
  echo ">>> installing UI deps (first run)"
  (cd "$UI_DIR" && pnpm install --frozen-lockfile)
fi

# dist/ is not committed; build it so the backend's go:embed serves a real UI
# on :8081 (the Vite dev server on :5000 has its own HMR build).
echo ">>> building UI (dist/ is generated, not committed)"
(cd "$UI_DIR" && pnpm build)

# Track child PIDs and tear the whole group down on exit.
pids=()
cleanup() {
  trap - INT TERM EXIT
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo ">>> dashboard API  : http://localhost:8081"
echo ">>> dashboard UI   : http://localhost:5000  (use this one)"
echo ">>> login          : admin / devpassword"

# Backend (dev DB, dev login + API key under .dev/).
scripts/dev-dashboard.sh 2>&1 | sed 's/^/[api] /' &
pids+=($!)

# Wait for the backend before starting Vite, so the proxy doesn't spew
# ECONNREFUSED while the first `go run` compile is still in flight.
echo ">>> waiting for backend on :8081 (first compile can take a while)..."
for _ in $(seq 1 120); do
  if curl -sf http://localhost:8081/health >/dev/null 2>&1; then
    echo ">>> backend up"
    break
  fi
  sleep 1
done

# Frontend with HMR, proxying /api to the backend.
(cd "$UI_DIR" && pnpm dev) 2>&1 | sed 's/^/[ui]  /' &
pids+=($!)

if [ "$TRAFFIC" = true ]; then
  go run ./dashboard/cmd/dev-traffic-gen 2>&1 | sed 's/^/[gen] /' &
  pids+=($!)
fi

wait
