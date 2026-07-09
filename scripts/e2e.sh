#!/usr/bin/env bash
# E2e suite runner, used by CI and runnable locally:
#   FILTER_MODE=https scripts/e2e.sh            # all phases, shared baseline stack
#   FILTER_MODE=dns   scripts/e2e.sh 09 13      # only the given phase prefixes
# Brings the examples/build stack up (unless E2E_SKIP_INITIAL_UP=1, for phases that
# recreate the stack themselves), runs the phases, dumps logs on failure, tears down.
E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tests/e2e" && pwd)"
source "$E2E_DIR/lib.sh"

PHASES=("$@")

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

if [ ${#PHASES[@]} -eq 0 ]; then
  log "Starting e2e suite in $FILTER_MODE mode (all phases)"
else
  log "Starting e2e suite in $FILTER_MODE mode (phases: ${PHASES[*]})"
fi

if [ "${E2E_SKIP_INITIAL_UP:-0}" != "1" ]; then
  baseline_policy
  stack_up
  wait_ready
else
  log "Skipping initial baseline bring-up (E2E_SKIP_INITIAL_UP=1)"
fi

run_phase() {
  log ">>> Running $(basename "$1")"
  bash "$1"
}

if [ ${#PHASES[@]} -eq 0 ]; then
  for phase in "$E2E_DIR"/[0-9][0-9]_*.sh; do
    run_phase "$phase"
  done
else
  for n in "${PHASES[@]}"; do
    matches=("$E2E_DIR/${n}"_*.sh)
    if [ ! -e "${matches[0]}" ]; then
      fail "no phase script matches prefix '$n' in $E2E_DIR"
    fi
    for phase in "${matches[@]}"; do
      run_phase "$phase"
    done
  done
fi

log "e2e phases passed in $FILTER_MODE mode"
