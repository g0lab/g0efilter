#!/usr/bin/env bash
# Standalone load/stress runner for local iteration and scaled-up CI.
#   FILTER_MODE=https scripts/load.sh
#   LOAD_TOTAL=2000 LOAD_CONCURRENCY=100 scripts/load.sh
E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tests/e2e" && pwd)"
source "$E2E_DIR/lib.sh"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    log "FAILED (exit $status) - dumping container logs"
    dump_logs
  fi
  baseline_policy
  stack_down
  exit "$status"
}
trap cleanup EXIT

log "Starting load test in $FILTER_MODE mode"

baseline_policy
stack_up
wait_ready

bash "$E2E_DIR/12_load.sh"

log "Load test passed in $FILTER_MODE mode"
