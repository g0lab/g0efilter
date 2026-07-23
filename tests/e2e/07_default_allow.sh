#!/usr/bin/env bash
# Phase 5: default_action: allow + denylist (live policy reload, no restart).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 5: default-allow with denylist [$FILTER_MODE mode] ==="

seed_policy "default_action: 'allow'
allowlist:
  domains:
    - 'api.github.com'
denylist:
  ips:
    - '1.0.0.1'
  domains:
    - 'github.com'
    - '*.github.com'
    - 'google.com'
    - '*.google.com'"
wait_for_policy_reload

# Unlisted destination passes under default-allow
assert_allowed https://example.com

# Denylisted domains are blocked
assert_blocked https://google.com
assert_blocked http://google.com
assert_blocked https://github.com

# Explicit allowlist entry overrides the denylist
assert_allowed https://api.github.com

# Denylisted IP is dropped by nftables (both modes enforce IP denies in the filter chain)
assert_blocked https://1.0.0.1

log "OK: default-allow denylist enforced"
