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
[ -n "${DOCKER_CALLS:-}" ] && printf '%s\n' "$*" >> "$DOCKER_CALLS"
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
    DOCKER_CALLS="$WORK/docker.log" \
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

rm -rf "$WORK/tmp"
: > "$WORK/docker.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  DOCKER_CALLS="$WORK/docker.log" bash "$SETUP" > /dev/null 2>&1
if grep -Fq -- 'BRIDGE_INTERFACES=docker0,br-*' "$WORK/docker.log"; then
  echo "ok: Docker bridge interfaces are filtered"
  pass=$((pass + 1))
else
  echo "FAIL: Docker bridge interfaces are not filtered"
  fail=$((fail + 1))
fi

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

# check <condition-description> <name>: records a pass or a failure.
check() {
  if [ "$1" = "0" ]; then
    echo "ok: $2"
    pass=$((pass + 1))
  else
    echo "FAIL: $2"
    fail=$((fail + 1))
  fi
}

# The manifest feeds the job summary; a regex entry must survive JSON encoding
# intact or the report misreports the policy that was actually loaded.
rm -rf "$WORK/tmp"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  ALLOWED_DOMAINS=$'example.org\n/^cache-[0-9]+\\.example\\.com$/\n\n*.wild.test' \
  ALLOWED_IPS=$'10.0.0.0/8\n' \
  bash "$SETUP" > "$WORK/setup.out" 2>&1

MANIFEST="$WORK/tmp/g0efilter/policy-manifest.json"
[ -f "$MANIFEST" ]
check $? "setup.sh writes a policy manifest"

NODE="$(command -v node || true)"
if [ -n "$NODE" ]; then
  "$NODE" -e '
    const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const eq = (got, want, what) => {
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        console.error(what + ": got " + JSON.stringify(got) + ", want " + JSON.stringify(want));
        process.exit(1);
      }
    };
    eq(m.inputDomains, ["example.org", "/^cache-[0-9]+\\.example\\.com$/", "*.wild.test"], "inputDomains");
    eq(m.inputIPs, ["10.0.0.0/8"], "inputIPs");
    eq(m.mode, "https", "mode");
    eq(m.policy, "block", "policy");
    if (!m.baseDomains.includes("github.com")) { console.error("baseDomains missing github.com"); process.exit(1); }
    if (m.baseDomains.some((d) => m.inputDomains.includes(d))) { console.error("baseline and input overlap"); process.exit(1); }
  ' "$MANIFEST"
  check $? "manifest records the workflow and baseline entries separately"
else
  echo "skip: node not installed, manifest contents not checked"
fi

grep -q "::group::g0efilter allowlist" "$WORK/setup.out"
check $? "setup.sh logs the loaded allowlist as a workflow group"

grep -q "  + example.org" "$WORK/setup.out"
check $? "workflow domains are marked in the logged allowlist"

# Every manifest entry must also be in the policy the filter actually loads.
POLICY_YAML="$WORK/tmp/g0efilter/policy/policy.yaml"
grep -q "'/\^cache-\[0-9\]+\\\\.example\\\\.com\$/'" "$POLICY_YAML" \
  && grep -q "'10.0.0.0/8'" "$POLICY_YAML" \
  && grep -q "'github.com'" "$POLICY_YAML"
check $? "policy.yaml carries the same entries verbatim"

# An empty allowlist input must not produce a blank YAML entry, which would
# widen the policy to an empty-string domain.
rm -rf "$WORK/tmp"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" bash "$SETUP" > /dev/null 2>&1
! grep -q "^    - ''$" "$WORK/tmp/g0efilter/policy/policy.yaml"
check $? "no empty allowlist entries with no inputs"

# Alerts name the workflow, not the throwaway runner hostname.
rm -rf "$WORK/tmp"
: > "$WORK/docker.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  DOCKER_CALLS="$WORK/docker.log" \
  GITHUB_REPOSITORY=g0lab/g0efilter GITHUB_WORKFLOW=build \
  bash "$SETUP" > /dev/null 2>&1
grep -Fq -- 'HOSTNAME=g0lab/g0efilter/build' "$WORK/docker.log"
check $? "identity defaults to repository and workflow"

rm -rf "$WORK/tmp"
: > "$WORK/docker.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  DOCKER_CALLS="$WORK/docker.log" IDENTITY=prod-runner \
  bash "$SETUP" > /dev/null 2>&1
grep -Fq -- 'HOSTNAME=prod-runner' "$WORK/docker.log"
check $? "identity input overrides the default"

# A URL in argv is readable by any user running ps, so it goes via the environment.
rm -rf "$WORK/tmp"
: > "$WORK/docker.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  DOCKER_CALLS="$WORK/docker.log" \
  NOTIFICATION_URLS="ntfy://ntfy.example.com/secret-topic" \
  bash "$SETUP" > /dev/null 2>&1
grep -Fq -- '-e NOTIFICATION_URLS' "$WORK/docker.log"
check $? "notification urls are passed by name, not by value"

! grep -Fq -- 'secret-topic' "$WORK/docker.log"
check $? "the notification token never reaches the docker command line"

# The action takes newline-separated rules; the filter parses commas.
rm -rf "$WORK/tmp"
: > "$WORK/docker.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  DOCKER_CALLS="$WORK/docker.log" \
  NOTIFICATION_IGNORE="$(printf 'local\n*.telemetry.example.com')" \
  bash "$SETUP" > /dev/null 2>&1
grep -Fq -- 'NOTIFICATION_IGNORE_DOMAINS=local,*.telemetry.example.com' "$WORK/docker.log"
check $? "notification ignore rules are converted to the filter's format"

rm -rf "$WORK/tmp"
: > "$WORK/docker.log"
env -i PATH="$WORK/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK/tmp" \
  DOCKER_CALLS="$WORK/docker.log" bash "$SETUP" > /dev/null 2>&1
! grep -Fq -- 'NOTIFICATION_URLS' "$WORK/docker.log"
check $? "no notification config when the input is unset"

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
