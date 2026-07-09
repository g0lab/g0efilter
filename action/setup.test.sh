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

# Stub sudo so the lockdown accept path does not run real chown/chmod (which
# would brick sudo on the test machine). Logs each invocation so tests can
# assert the exact lockdown command sequence.
cat > "$WORK/bin/sudo" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$WORK/sudo.log"
exit 0
EOF
chmod +x "$WORK/bin/sudo"

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
run_setup 1 "lockdown-runner must be" "invalid lockdown-runner rejected" LOCKDOWN_RUNNER=maybe

# Accept paths run through to the stubbed container and exit 0.
run_setup 0 "" "defaults accepted"
run_setup 0 "" "mode dns accepted" FILTER_MODE=dns
run_setup 0 "" "mode dns-strict accepted" FILTER_MODE=dns-strict
run_setup 0 "" "egress-policy audit accepted" EGRESS_POLICY=audit
run_setup 0 "" "log-level lowercase accepted" LOG_LEVEL=debug
run_setup 0 "" "log-level WARNING alias accepted" LOG_LEVEL=WARNING
run_setup 0 "" "log-level TRACE accepted" LOG_LEVEL=TRACE
run_setup 0 "Lockdown applied" "lockdown-runner true applies lockdown" \
  LOCKDOWN_RUNNER=true RUNNER_ENVIRONMENT=github-hosted
run_setup 1 "requires a GitHub-hosted runner" "lockdown-runner rejects non-hosted runner" \
  LOCKDOWN_RUNNER=true RUNNER_ENVIRONMENT=self-hosted

# Lockdown must lock the Docker socket before disabling sudo: the reverse order
# would leave the socket world-accessible once sudo is gone.
: > "$WORK/sudo.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  LOCKDOWN_RUNNER=true RUNNER_ENVIRONMENT=github-hosted \
  bash "$SETUP" > /dev/null 2>&1
got_seq="$(cat "$WORK/sudo.log" 2>/dev/null)"
want_seq="chown root:root /var/run/docker.sock
chmod 0600 /var/run/docker.sock
chmod 000 /usr/bin/sudo"
if [ "$got_seq" = "$want_seq" ]; then
  echo "ok: lockdown locks socket before disabling sudo"
  pass=$((pass + 1))
else
  echo "FAIL: lockdown command sequence"
  printf '  got:\n%s\n' "$got_seq"
  fail=$((fail + 1))
fi

# No lockdown when disabled: sudo must not be touched at all.
: > "$WORK/sudo.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" LOCKDOWN_RUNNER=false \
  bash "$SETUP" > /dev/null 2>&1
if [ ! -s "$WORK/sudo.log" ]; then
  echo "ok: no lockdown when lockdown-runner is false"
  pass=$((pass + 1))
else
  echo "FAIL: lockdown ran with lockdown-runner=false"
  printf '  got:\n%s\n' "$(cat "$WORK/sudo.log")"
  fail=$((fail + 1))
fi

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
