#!/usr/bin/env bash
# Phase 13: dns/dns-strict modes resolve a non-domain-allowlisted host when it
# points at an allowlisted IP, matching HTTPS-mode behaviour. The behaviour only
# activates when the policy has IP allowlist entries. The same
# handleNotPermitted -> resolveViaIPAllowlist path serves both lanes, so run in
# each (skipping https).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "dns" ] && [ "$FILTER_MODE" != "dns-strict" ]; then
  log "Skipping dns IP-allowlist phase in $FILTER_MODE matrix (dns lanes only)"
  exit 0
fi

log "=== Phase 13: $FILTER_MODE mode IP-allowlist domain resolution ==="

# Allowlist Cloudflare's 1.1.1.1 by IP only; its domain one.one.one.one is not
# domain-allowlisted.
seed_policy '---
allowlist:
  ips:
    - "1.1.1.1"
  domains:
    - "github.com"'
stack_up
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

log "OK: $FILTER_MODE mode IP-allowlist resolution verified"
