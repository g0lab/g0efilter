#!/usr/bin/env bash
# UI test runner, used by CI and runnable locally:
#   scripts/test-ui.sh
# Installs deps from the frozen lockfile, type-checks (svelte-check), lints
# (eslint: typescript-eslint + eslint-plugin-svelte), and verifies the embedded
# dist/ builds cleanly. dist/ is not committed - it is generated here and by the
# Docker/release build. Requires Node 24 + pnpm.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/dashboard/ui"

echo ">>> pnpm install (frozen lockfile)"
pnpm install --frozen-lockfile

echo ">>> type-check (svelte-check)"
pnpm check

echo ">>> lint (eslint)"
pnpm lint

echo ">>> build (embedded dist/)"
pnpm build
