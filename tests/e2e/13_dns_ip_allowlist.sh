#!/usr/bin/env bash
# Phase 13: dns mode resolves a non-domain-allowlisted host when it points at an
# allowlisted IP, matching HTTPS-mode behaviour. The behaviour only
# activates when the policy has IP allowlist entries. Runs in the dns lane only.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "dns" ]; then
  log "Skipping dns IP-allowlist phase in $FILTER_MODE matrix (runs once, in the dns lane)"
  exit 0
fi

log "=== Phase 13: dns mode IP-allowlist domain resolution ==="

# Allowlist Cloudflare's 1.1.1.1 by IP only; its domain one.one.one.one is not
# domain-allowlisted.
seed_policy '---
allowlist:
  ips:
    - "1.1.1.1"
  domains:
    - "github.com"'
stack_up FILTER_MODE=dns
wait_ready

log "[IP-allowlist] Non-allowlisted domain pointing at an allowlisted IP resolves and connects"
assert_allowed https://one.one.one.one

log "[IP-allowlist] Domain not resolving to an allowlisted IP stays blocked"
assert_blocked https://example.com

log "[IP-allowlist] Directly allowlisted IP still works"
assert_allowed https://1.1.1.1

# Remove the IP allowlist: the resolve-and-check behaviour must switch off.
seed_policy '---
allowlist:
  domains:
    - "github.com"'
wait_for_policy_reload

log "[IP-allowlist] With no IPs in policy, the same domain is blocked again"
assert_blocked https://one.one.one.one

log "OK: dns mode IP-allowlist resolution verified"
