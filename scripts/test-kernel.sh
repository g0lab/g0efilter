#!/usr/bin/env bash
# Runs the nftables kernel tests in a disposable container with its own network
# namespace, so the host's ruleset is never touched. Needs Docker. Extra arguments
# go to `go test`; G0EFILTER_PARITY_ROUNDS and G0EFILTER_PARITY_SEED pass through.
#
#   scripts/test-kernel.sh [-v] [-run 'TestKernel...']
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The agent's own builder, so Renovate's bumps reach the kernel tests too.
IMAGE="$(grep -o -m1 'golang:[^ ]*' "$ROOT/agent/Containerfile")"

# The TAP device and forwarding let the bridge tests route a container's frames.
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  -v "$ROOT":/src -w /src/agent \
  -v "$(go env GOMODCACHE)":/go/pkg/mod \
  -e GOFLAGS=-buildvcs=false -e GOWORK=off -e CGO_ENABLED=0 -e G0EFILTER_KERNEL_TESTS=1 \
  -e G0EFILTER_PARITY_ROUNDS -e G0EFILTER_PARITY_SEED \
  "$IMAGE" sh -c 'apk add --no-cache nftables iproute2 >/dev/null &&
    go test -count=1 -run "^TestKernel" "$@" ./nftables/' sh "$@"
