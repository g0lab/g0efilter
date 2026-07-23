#!/usr/bin/env bash
# Phase 4: /regex/ and mid-name wildcard domain patterns (live policy reload, no restart).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 4: regex domain patterns [$FILTER_MODE mode] ==="

seed_policy "allowlist:
  domains:
    - '/^(www\\.)?github\\.com$/'"
wait_for_policy_reload

assert_allowed https://github.com
assert_allowed https://www.github.com

# Anchored regex: sibling subdomains must not match
assert_blocked https://api.github.com
assert_blocked https://google.com

log "OK: regex allowlist pattern enforced"

log "=== Phase 4b: mid-name wildcard patterns [$FILTER_MODE mode] ==="

seed_policy "allowlist:
  domains:
    - 'www.*.com'"
wait_for_policy_reload

# '*' between labels spans one or more characters
assert_allowed https://www.github.com

# The literal parts are still required
assert_blocked https://github.com
assert_blocked https://api.github.com

log "OK: mid-name wildcard pattern enforced"
