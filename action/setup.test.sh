#!/usr/bin/env bash
# Unit tests for setup.sh input validation (mode, egress-policy, log-level).
# Runs setup.sh with a stubbed docker so accept paths exit without a real
# container. Dependency-free: run with `bash action/setup.test.sh`.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP="$HERE/setup.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Stub docker: run/ps/rm succeed, logs reports the readiness marker so the
# accept path exits 0 without a real container.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  logs) echo "startup.ready" ;;
  ps)   echo "container123" ;;
esac
exit 0
EOF
chmod +x "$WORK/bin/docker"

pass=0
fail=0

# run_setup <expected_exit> <needle> <name> [ENV=val ...]
run_setup() {
  local want="$1" needle="$2" name="$3"; shift 3
  local out rc
  out="$(env -i \
    PATH="$WORK/bin:/usr/bin:/bin" \
    RUNNER_TEMP="$WORK/tmp" \
    "$@" \
    bash "$SETUP" 2>&1)"
  rc=$?

  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $name (exit $rc, want $want)"
    echo "  output: $out"
    fail=$((fail + 1))
    return
  fi
  if [ -n "$needle" ] && [[ "$out" != *"$needle"* ]]; then
    echo "FAIL: $name (missing '$needle')"
    echo "  output: $out"
    fail=$((fail + 1))
    return
  fi
  echo "ok: $name"
  pass=$((pass + 1))
}

# Reject paths exit 1 before touching docker.
run_setup 1 "mode must be" "invalid mode rejected" FILTER_MODE=bogus
run_setup 1 "egress-policy must be" "invalid egress-policy rejected" EGRESS_POLICY=bogus
run_setup 1 "log-level must be" "invalid log-level rejected" LOG_LEVEL=verbose

# Accept paths run through to the stubbed container and exit 0.
run_setup 0 "" "defaults accepted"
run_setup 0 "" "mode dns accepted" FILTER_MODE=dns
run_setup 0 "" "mode dns-strict accepted" FILTER_MODE=dns-strict
run_setup 0 "" "egress-policy audit accepted" EGRESS_POLICY=audit
run_setup 0 "" "log-level lowercase accepted" LOG_LEVEL=debug
run_setup 0 "" "log-level WARNING alias accepted" LOG_LEVEL=WARNING
run_setup 0 "" "log-level TRACE accepted" LOG_LEVEL=TRACE

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
