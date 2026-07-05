#!/usr/bin/env bash
# Starts g0efilter on the runner host (host network + NET_ADMIN) and waits until
# the policy is applied. Inputs arrive as env vars via action/main.js.
set -euo pipefail

MODE="${FILTER_MODE:-https}"
POLICY="${EGRESS_POLICY:-block}"

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
  https|dns) ;;
  *) echo "::error::mode must be 'https' or 'dns' (got '$MODE')"; exit 1 ;;
esac
case "$POLICY" in
  block|audit) ;;
  *) echo "::error::egress-policy must be 'block' or 'audit' (got '$POLICY')"; exit 1 ;;
esac

WORKDIR="${RUNNER_TEMP:-/tmp}/g0efilter"
mkdir -p "$WORKDIR/policy"
POLICY_FILE="$WORKDIR/policy/policy.yaml"

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

# YAML single-quoted so regex/wildcard entries survive verbatim.
yaml_entry() {
  local v="${1//\'/\'\'}"
  printf "    - '%s'\n" "$v"
}

{
  echo "---"
  echo "allowlist:"
  echo "  domains:"
  for d in "${BASE_DOMAINS[@]}"; do yaml_entry "$d"; done
  while read -r d; do
    [ -n "$d" ] && yaml_entry "$d"
  done <<< "${ALLOWED_DOMAINS:-}"
  echo "  ips:"
  for ip in "${BASE_IPS[@]}"; do yaml_entry "$ip"; done
  while read -r ip; do
    [ -n "$ip" ] && yaml_entry "$ip"
  done <<< "${ALLOWED_IPS:-}"
} > "$POLICY_FILE"

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
  -e LOG_LEVEL="${LOG_LEVEL:-INFO}"
)

# Host :53 is systemd-resolved; the NAT redirect still captures DNS to the
# proxy's alt port. Forward to the host's real resolvers - the default
# 127.0.0.11 (Docker DNS) is absent on the host net, and a dead upstream with
# every :53 redirected takes out the whole runner's DNS.
if [ "$MODE" = "dns" ]; then
  # Match v4 and v6 resolvers; bracket v6 for host:port form.
  UPSTREAMS=$(awk '/^nameserver[ \t]+[0-9a-fA-F:.]+/ {ip=$2; if (ip ~ /:/) ip="[" ip "]"; printf "%s%s:53", sep, ip; sep=","}' "$RESOLV_SRC" 2>/dev/null)
  [ -n "$UPSTREAMS" ] && DOCKER_ARGS+=(-e DNS_UPSTREAMS="$UPSTREAMS")
  DOCKER_ARGS+=(-e DNS_PORT=5353)
fi

docker run "${DOCKER_ARGS[@]}" "$IMAGE"

echo "Waiting for the filter to become ready..."
for _ in $(seq 1 60); do
  # startup.ready covers all released versions; policy.applied is the reload marker
  if docker logs g0efilter 2>&1 | grep -qE "startup\.ready|policy\.applied"; then
    echo "g0efilter is active - egress is now filtered ($POLICY mode)"
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
