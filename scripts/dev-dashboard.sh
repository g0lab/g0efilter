#!/usr/bin/env bash
# Local dashboard dev backend:
#   scripts/dev-dashboard.sh
# Runs g0efilter-dashboard on :8081 with session auth, a persistent dev
# database under .dev/, 10,000 historical log fixtures, and a known dev login
# + API key. Pair with the
# frontend dev server (cd dashboard/ui && pnpm dev) for HMR, or hit
# :8081 directly to use the embedded build.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEV_DIR="$ROOT/.dev"
mkdir -p "$DEV_DIR"

DEV_USER="${DEV_USER:-admin}"
DEV_PASSWORD="${DEV_PASSWORD:-devpassword}"
DEV_API_KEY="${DEV_API_KEY:-dev-api-key}"
DEV_SEED_COUNT="${DEV_SEED_COUNT:-10000}"

if [ "$DEV_SEED_COUNT" != "0" ]; then
  echo ">>> replacing dev traffic logs with $DEV_SEED_COUNT seeded events"
  go run ./scripts/dev-seed-dashboard -db "$DEV_DIR/dashboard.db" -count "$DEV_SEED_COUNT"
fi

HASH=$(printf '%s\n' "$DEV_PASSWORD" | go run ./dashboard hash-password)

echo ">>> dashboard: http://localhost:8081"
echo ">>> login:     $DEV_USER / $DEV_PASSWORD"
echo ">>> api key:   $DEV_API_KEY   (dev-traffic-gen uses this)"
echo ">>> db:        $DEV_DIR/dashboard.db"

AUTH_MODE=session \
ADMIN_USERNAME="$DEV_USER" \
ADMIN_PASSWORD_HASH="$HASH" \
API_KEY="$DEV_API_KEY" \
DB_PATH="$DEV_DIR/dashboard.db" \
COOKIE_SECURE=false \
PORT=":8081" \
LOG_LEVEL="${LOG_LEVEL:-DEBUG}" \
exec go run ./dashboard
