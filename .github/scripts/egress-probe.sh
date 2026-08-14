#!/usr/bin/env bash
# Egress probes for .github/workflows/action-test.yaml. Each subcommand is one
# workflow step: it proves one property of a running filter, prints what it proved,
# and exits non-zero when the filter did not behave.
#
#   egress-probe.sh reach https://api.github.com        # must connect
#   egress-probe.sh denied https://example.com          # must not connect
#   egress-probe.sh reach-http http://api.github.com    # as above, status ignored
#   egress-probe.sh denied-http http://example.com
#   egress-probe.sh docker-reach host https://api.github.com
#   egress-probe.sh docker-denied default https://example.com --max-time 10
#   egress-probe.sh bridge-check <network|default> <allowed-url> <blocked-url>
#   egress-probe.sh peer-reach <network> <port>
#   egress-probe.sh tcp-denied 8.8.8.8 53
#   egress-probe.sh nft-bridge-tables
#   egress-probe.sh nft-ipv6-tables
#   egress-probe.sh pull-image [image]
#
# reach/denied pass --fail, so an HTTP error status counts as unreachable. The
# -http pair does not: the filter answers blocked HTTP with an error page, and
# those steps assert the connection itself never completes.
set -euo pipefail

CURL_IMAGE=curlimages/curl:latest
BASE=(--silent --show-error --connect-timeout 10 --max-time 20)
RETRY=(--retry 2 --retry-delay 2 --retry-all-errors)

die() {
  echo "$*" >&2
  exit 1
}

# `default` means Docker's own bridge, so no --network flag at all.
network_args() {
  case "$1" in
    default) ;;
    *) printf '%s\n' --network "$1" ;;
  esac
}

cmd_reach() {
  local url="$1"
  shift
  curl --fail "${BASE[@]}" "${RETRY[@]}" "$@" "$url" -o /dev/null ||
    die "$url should have been reachable"
  echo "OK: $url reachable"
}

cmd_denied() {
  local url="$1"
  shift
  if curl --fail "${BASE[@]}" "$@" "$url" -o /dev/null; then
    die "$url should have been blocked"
  fi
  echo "OK: $url blocked"
}

cmd_reach_http() {
  local url="$1"
  shift
  curl "${BASE[@]}" "${RETRY[@]}" "$@" "$url" -o /dev/null ||
    die "$url should have been reachable"
  echo "OK: $url reachable"
}

cmd_denied_http() {
  local url="$1"
  shift
  if curl "${BASE[@]}" "$@" "$url" -o /dev/null; then
    die "$url should have been blocked"
  fi
  echo "OK: $url blocked"
}

cmd_docker_reach() {
  local network="$1" url="$2"
  shift 2
  mapfile -t net < <(network_args "$network")
  docker run --rm "${net[@]}" "$CURL_IMAGE" \
    --fail "${BASE[@]}" "${RETRY[@]}" "$@" "$url" -o /dev/null ||
    die "$url should have been reachable from the $network network"
  echo "OK: $url reachable from the $network network"
}

cmd_docker_denied() {
  local network="$1" url="$2"
  shift 2
  mapfile -t net < <(network_args "$network")
  if docker run --rm "${net[@]}" "$CURL_IMAGE" \
    --fail "${BASE[@]}" "$@" "$url" -o /dev/null; then
    die "the $network network bypassed the filter"
  fi
  echo "OK: $network network traffic filtered"
}

# A named network is created here and torn down on exit, which is what proves a
# bridge built after the filter started is still filtered.
cmd_bridge_check() {
  local network="$1" allowed="$2" blocked="$3"

  if [ "$network" != default ]; then
    docker network create "$network" > /dev/null
    # shellcheck disable=SC2064 # the name must expand now, not at trap time
    trap "docker network rm '$network' >/dev/null 2>&1 || true" EXIT
  fi

  cmd_docker_reach "$network" "$allowed"
  cmd_docker_denied "$network" "$blocked"
}

# Containers sharing a bridge must still reach each other: the filter redirects
# egress, not traffic that never leaves the bridge.
cmd_peer_reach() {
  local network="$1" port="$2"
  local peer_name="g0efilter-peer-$port"
  local user=()

  # Binding port 80 in the container needs root, unlike the unprivileged ports.
  if [ "$port" -lt 1024 ]; then
    user=(--user 0)
  fi

  docker network create "$network" > /dev/null
  # shellcheck disable=SC2064 # both names must expand now, not at trap time
  trap "docker rm -f '$peer_name' >/dev/null 2>&1 || true
        docker network rm '$network' >/dev/null 2>&1 || true" EXIT

  docker run -d --name "$peer_name" "${user[@]}" \
    --network "$network" "$CURL_IMAGE" nc -l -p "$port" > /dev/null

  local peer=""
  for _ in 1 2 3 4 5; do
    peer=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_name")
    [ -n "$peer" ] && break
    sleep 1
  done

  if [ -z "$peer" ]; then
    docker logs "$peer_name" || true
    die "the peer container never reported an address"
  fi

  docker run --rm --network "$network" "$CURL_IMAGE" \
    sh -c "echo ping | nc -w 5 $peer $port" ||
    die "container to container traffic on port $port must not be filtered"

  echo "OK: same-bridge traffic on port $port was not filtered"
}

# The host is otherwise reachable, so a refused connection confirms filtering.
cmd_tcp_denied() {
  local host="$1" port="$2"

  if timeout 10 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2> /dev/null; then
    die "TCP/$port to $host should have been blocked"
  fi
  echo "OK: TCP/$port to $host blocked"
}

cmd_nft_bridge_tables() {
  sudo nft list table ip g0efilter_bridge_v4 | grep -F 'iifname "docker0" jump bridge_egress'
  sudo nft list table ip g0efilter_bridge_v4 | grep -F 'iifname "br-*" jump bridge_egress'
  sudo nft list table ip g0efilter_bridge_nat_v4 > /dev/null
  echo "OK: bridge tables and the future-network wildcard are installed"
}

cmd_nft_ipv6_tables() {
  sudo nft list table ip6 g0efilter_v6 > /dev/null
  sudo nft list table ip6 g0efilter_nat_v6 > /dev/null
  echo "OK: IPv6 filter tables present"
}

# Pulled before the filter starts: the registry is not allowlisted.
cmd_pull_image() {
  local image="${1:-$CURL_IMAGE}"

  for attempt in 1 2 3; do
    if docker pull "$image"; then
      return 0
    fi
    if [ "$attempt" -eq 3 ]; then
      die "could not pull $image"
    fi
    sleep $((attempt * 2))
  done
}

main() {
  [ $# -gt 0 ] || die "usage: egress-probe.sh <subcommand> [args...]"

  local subcommand="$1"
  shift

  case "$subcommand" in
    reach) cmd_reach "$@" ;;
    denied) cmd_denied "$@" ;;
    reach-http) cmd_reach_http "$@" ;;
    denied-http) cmd_denied_http "$@" ;;
    docker-reach) cmd_docker_reach "$@" ;;
    docker-denied) cmd_docker_denied "$@" ;;
    bridge-check) cmd_bridge_check "$@" ;;
    peer-reach) cmd_peer_reach "$@" ;;
    tcp-denied) cmd_tcp_denied "$@" ;;
    nft-bridge-tables) cmd_nft_bridge_tables "$@" ;;
    nft-ipv6-tables) cmd_nft_ipv6_tables "$@" ;;
    pull-image) cmd_pull_image "$@" ;;
    *) die "unknown subcommand: $subcommand" ;;
  esac
}

main "$@"
