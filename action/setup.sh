#!/usr/bin/env bash
# Starts g0efilter on the runner host (host network + NET_ADMIN) and waits until
# the policy is applied. Inputs arrive as env vars via action/main.js.
set -euo pipefail

MODE="${FILTER_MODE:-https}"
POLICY="${EGRESS_POLICY:-block}"
LOG_LEVEL_VALUE="${LOG_LEVEL:-INFO}"

# Default image: the release matching the action's tag, so pinning the action
# pins the filter too; :latest when used via a branch ref.
IMAGE="${G0EFILTER_IMAGE:-}"
if [ -z "$IMAGE" ]; then
  case "${GITHUB_ACTION_REF:-}" in
    v[0-9]*) IMAGE="docker.io/g0lab/g0efilter:${GITHUB_ACTION_REF}" ;;
    *) IMAGE="docker.io/g0lab/g0efilter:latest" ;;
  esac
fi

case "$MODE" in
  https|dns|dns-strict) ;;
  *) echo "::error::mode must be 'https', 'dns', or 'dns-strict' (got '$MODE')"; exit 1 ;;
esac
case "$POLICY" in
  block|audit) ;;
  *) echo "::error::egress-policy must be 'block' or 'audit' (got '$POLICY')"; exit 1 ;;
esac
case "${LOG_LEVEL_VALUE^^}" in
  TRACE|DEBUG|INFO|WARN|WARNING|ERROR) LOG_LEVEL_VALUE="${LOG_LEVEL_VALUE^^}" ;;
  *) echo "::error::log-level must be one of TRACE, DEBUG, INFO, WARN, or ERROR (got '$LOG_LEVEL_VALUE')"; exit 1 ;;
esac
[ "$LOG_LEVEL_VALUE" = "WARNING" ] && LOG_LEVEL_VALUE="WARN"

LOCKDOWN="${LOCKDOWN_RUNNER:-false}"
case "$LOCKDOWN" in
  true|false) ;;
  *) echo "::error::lockdown-runner must be 'true' or 'false' (got '$LOCKDOWN')"; exit 1 ;;
esac

# GitHub-hosted only: disable later sudo/Docker so a later step cannot undo the hardening.
apply_lockdown() {
  [ "$LOCKDOWN" = "true" ] || return 0
  if [ "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]; then
    echo "::error::lockdown-runner requires a GitHub-hosted runner"
    exit 1
  fi
  echo "Applying runner lockdown (GitHub-hosted runners only)"
  # Socket first, while sudo still works; the daemon (and g0efilter) keeps running.
  # Fail closed: a failed hardening step must abort, not silently report success.
  sudo chown root:root /var/run/docker.sock
  sudo chmod 0600 /var/run/docker.sock
  sudo chmod 000 /usr/bin/sudo
  echo "Lockdown applied: later sudo and Docker access disabled; teardown will be skipped"
}

WORKDIR="${RUNNER_TEMP:-/tmp}/g0efilter"
mkdir -p "$WORKDIR/policy"
POLICY_FILE="$WORKDIR/policy/policy.yaml"
MANIFEST_FILE="$WORKDIR/policy-manifest.json"

# GitHub's documented runner communication domains
# (https://docs.github.com/actions/reference/runners/self-hosted-runners).
# Deliberately no ghcr.io / *.pkg.github.com: pulling packages or containers is
# a workflow concern, not runner baseline - add via allowed-domains if needed.
BASE_DOMAINS=(
  # Essential runner operation
  "github.com"
  "api.github.com"
  "*.actions.githubusercontent.com"

  # GitHub-hosted runner control plane (hosted-compute watchdog/orchestrator);
  # blocking these can get the runner VM reaped mid-job
  "*.githubapp.com"

  # Downloading actions
  "codeload.github.com"

  # Job summaries, logs, workflow artifacts and caches
  "results-receiver.actions.githubusercontent.com"
  "*.blob.core.windows.net"

  # Release/object downloads
  "objects.githubusercontent.com"
  "objects-origin.githubusercontent.com"
  "github-releases.githubusercontent.com"
  "github-registry-files.githubusercontent.com"
  "release-assets.githubusercontent.com"
)

# DNS must keep working under default-deny: allow the host's upstream resolvers
# and the Azure DNS/metadata endpoints GitHub-hosted runners depend on.
BASE_IPS=("168.63.129.16" "169.254.169.254")
RESOLV_SRC="/run/systemd/resolve/resolv.conf"
[ -f "$RESOLV_SRC" ] || RESOLV_SRC="/etc/resolv.conf"
while read -r ip; do
  BASE_IPS+=("$ip")
done < <(awk '/^nameserver/ {print $2}' "$RESOLV_SRC" 2>/dev/null || true)

INPUT_DOMAINS=()
while read -r d; do
  [ -n "$d" ] && INPUT_DOMAINS+=("$d")
done <<< "${ALLOWED_DOMAINS:-}"

INPUT_IPS=()
while read -r ip; do
  [ -n "$ip" ] && INPUT_IPS+=("$ip")
done <<< "${ALLOWED_IPS:-}"

# YAML single-quoted so regex/wildcard entries survive verbatim.
yaml_entry() {
  local v="${1//\'/\'\'}"
  printf "    - '%s'\n" "$v"
}

{
  echo "---"
  echo "allowlist:"
  echo "  domains:"
  for d in "${BASE_DOMAINS[@]}" "${INPUT_DOMAINS[@]}"; do yaml_entry "$d"; done
  echo "  ips:"
  for ip in "${BASE_IPS[@]}" "${INPUT_IPS[@]}"; do yaml_entry "$ip"; done
} > "$POLICY_FILE"

json_escape() {
  local v="${1//\\/\\\\}"
  printf '%s' "${v//\"/\\\"}"
}

json_array() {
  local sep="" v
  printf '['
  for v in "$@"; do
    printf '%s"%s"' "$sep" "$(json_escape "$v")"
    sep=","
  done
  printf ']'
}

# The post step reports the exact allowlist that was loaded; it reads this rather
# than re-parsing the YAML, so baseline and workflow entries stay distinguishable.
{
  printf '{"mode":"%s",' "$(json_escape "$MODE")"
  printf '"policy":"%s",' "$(json_escape "$POLICY")"
  printf '"image":"%s",' "$(json_escape "$IMAGE")"
  printf '"baseDomains":%s,' "$(json_array "${BASE_DOMAINS[@]}")"
  printf '"inputDomains":%s,' "$(json_array "${INPUT_DOMAINS[@]}")"
  printf '"baseIPs":%s,' "$(json_array "${BASE_IPS[@]}")"
  printf '"inputIPs":%s}\n' "$(json_array "${INPUT_IPS[@]}")"
} > "$MANIFEST_FILE"

echo "::group::g0efilter allowlist (${#BASE_DOMAINS[@]}+${#INPUT_DOMAINS[@]} domains, ${#BASE_IPS[@]}+${#INPUT_IPS[@]} IPs)"
echo "Domains from this workflow (${#INPUT_DOMAINS[@]}):"
for d in "${INPUT_DOMAINS[@]}"; do echo "  + $d"; done
echo "Baseline domains (${#BASE_DOMAINS[@]}):"
for d in "${BASE_DOMAINS[@]}"; do echo "    $d"; done
echo "IPs from this workflow (${#INPUT_IPS[@]}):"
for ip in "${INPUT_IPS[@]}"; do echo "  + $ip"; done
echo "Baseline IPs (${#BASE_IPS[@]}):"
for ip in "${BASE_IPS[@]}"; do echo "    $ip"; done
echo "::endgroup::"

ENFORCE="block"
[ "$POLICY" = "audit" ] && ENFORCE="audit"

echo "Starting g0efilter (image: $IMAGE, mode: $MODE, egress-policy: $POLICY)"

DOCKER_ARGS=(
  -d --name g0efilter
  --network host
  --cap-drop ALL --cap-add NET_ADMIN
  --security-opt no-new-privileges
  -v "$WORKDIR/policy/:/app/policy/"
  -e POLICY_PATH=/app/policy/policy.yaml
  -e FILTER_MODE="$MODE"
  -e ENFORCE="$ENFORCE"
  -e LOG_LEVEL="$LOG_LEVEL_VALUE"
  -e 'BRIDGE_INTERFACES=docker0,br-*'
)

# The runner hostname is ephemeral and meaningless in an alert.
IDENTITY="${IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
  IDENTITY="${GITHUB_REPOSITORY:-g0efilter}/${GITHUB_WORKFLOW:-workflow}"
fi
DOCKER_ARGS+=(-e HOSTNAME="$IDENTITY")

# Name-only -e: the value comes from this process's environment, so the token
# never lands in argv, where any user could read it via ps.
if [ -n "${NOTIFICATION_URLS:-}" ]; then
  export NOTIFICATION_URLS
  DOCKER_ARGS+=(-e NOTIFICATION_URLS)
  echo "Blocked-egress notifications enabled"
fi

if [ -n "${NOTIFICATION_IGNORE:-}" ]; then
  DOCKER_ARGS+=(-e NOTIFICATION_IGNORE_DOMAINS="$(printf '%s' "$NOTIFICATION_IGNORE" | tr '\n' ',')")
fi

# Host :53 is systemd-resolved; the NAT redirect still captures DNS to the
# proxy's alt port. Forward to the host's real resolvers - the default
# 127.0.0.11 (Docker DNS) is absent on the host net, and a dead upstream with
# every :53 redirected takes out the whole runner's DNS.
if [ "$MODE" = "dns" ] || [ "$MODE" = "dns-strict" ]; then
  # Match v4 and v6 resolvers; bracket v6 for host:port form.
  UPSTREAMS=$(awk '/^nameserver[ \t]+[0-9a-fA-F:.]+/ {ip=$2; if (ip ~ /:/) ip="[" ip "]"; printf "%s%s:53", sep, ip; sep=","}' "$RESOLV_SRC" 2>/dev/null)
  [ -n "$UPSTREAMS" ] && DOCKER_ARGS+=(-e DNS_UPSTREAMS="$UPSTREAMS")
  DOCKER_ARGS+=(-e DNS_PORT=65053)
fi

docker run "${DOCKER_ARGS[@]}" "$IMAGE"

echo "Waiting for the filter to become ready..."
for _ in $(seq 1 60); do
  # startup.ready covers all released versions; policy.applied is the reload marker
  if docker logs g0efilter 2>&1 | grep -qE "startup\.ready|policy\.applied"; then
    echo "g0efilter is active - egress is now filtered ($POLICY mode)"
    apply_lockdown
    exit 0
  fi
  if [ -z "$(docker ps -q --filter name=g0efilter)" ]; then
    break
  fi
  sleep 1
done

echo "::error::g0efilter failed to start - egress filtering is NOT active"
docker logs g0efilter 2>&1 | tail -50 || true
docker rm -f g0efilter > /dev/null 2>&1 || true
exit 1
