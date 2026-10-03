#!/usr/bin/env bash
# Runs the nftables kernel tests in a disposable container with its own network
# namespace, so the host's ruleset is never touched. Needs Docker.
#
#   scripts/test-kernel.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The agent's own builder, so Renovate's bumps reach the kernel tests too.
IMAGE="$(grep -o -m1 'golang:[^ ]*' "$ROOT/agent/Containerfile")"

docker run --rm --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  -v "$ROOT":/src -w /src/agent \
  -v "$(go env GOMODCACHE)":/go/pkg/mod \
  -e GOFLAGS=-buildvcs=false -e GOWORK=off -e CGO_ENABLED=0 -e G0EFILTER_KERNEL_TESTS=1 \
  "$IMAGE" sh -c 'apk add --no-cache nftables iproute2 >/dev/null && go test -count=1 -run "^TestKernel" ./nftables/'
