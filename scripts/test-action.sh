#!/usr/bin/env bash
# Action wrapper test runner, used by CI and runnable locally:
#   scripts/test-action.sh
# Syntax-checks the action scripts, runs their unit tests, and runs the
# setup.sh validation tests. Requires node and bash.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo ">>> node --check action scripts"
for f in action/*.js .github/test-actions/*/*.js; do
  node --check "$f"
done

echo ">>> bash -n workflow scripts"
for f in .github/scripts/*.sh; do
  bash -n "$f"
done

echo ">>> node --test action unit tests"
node --test 'action/*.test.js'

echo ">>> setup.sh validation tests"
bash action/setup.test.sh
