# End-to-end tests

Version-controlled e2e suite, run by CI (`.github/workflows/test.yaml`) and runnable locally.

## Run locally

Requires Docker with the compose plugin. From the repo root:

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns   scripts/e2e.sh
```

The dedicated dashboard phase also has an opt-in real-browser smoke test. It
requires Node 24, pnpm, and Playwright Chromium (CI installs these):

```sh
cd internal/dashboard/ui && pnpm install --frozen-lockfile
pnpm exec playwright install --with-deps chromium
cd ../../..
FILTER_MODE=https E2E_BROWSER=1 scripts/e2e.sh 14
```

`scripts/e2e.sh` builds and starts the `examples/build` stack, runs every phase, dumps
container logs on failure, and tears down (restoring the baseline policy file). This is
the recommended local run: all phases, one shared stack, in order.

To iterate on a single phase (or a few), pass their two-digit prefixes:

```sh
FILTER_MODE=dns scripts/e2e.sh 09           # just dns-strict
FILTER_MODE=dns E2E_SKIP_INITIAL_UP=1 scripts/e2e.sh 09   # skip the baseline bring-up
                                                          # (phase recreates the stack itself)
```

`E2E_SKIP_INITIAL_UP=1` is for the phases that recreate the stack themselves (08-11, 13-14);
it avoids bringing up a baseline stack that the phase immediately replaces. CI uses these
knobs to fan the suite out across parallel runners (see the matrix in `test.yaml`); locally
the phases share fixed container names and ports, so run them one stack at a time rather
than in parallel.

## Phases

| Script | Covers |
|---|---|
| `01_baseline.sh` | allow/block for domains and IPs against the baseline policy |
| `02_ipv6_egress.sh` | IPv6 egress blocked with no IPv6 policy entries (https mode) |
| `03_unblock_reload.sh` | dashboard remote-unblock API -> live policy reload, API error paths |
| `04_ipv6_unblock.sh` | IPv6 remote unblock -> nftables set update (https mode) |
| `05_dashboard_logs.sh` | proxy -> dashboard log ingestion end-to-end |
| `06_regex.sh` | `/regex/` and mid-name wildcard (`www.*.com`) domain patterns |
| `07_default_allow.sh` | `default_action: allow` + denylist (domains, IPs, allowlist override) |
| `08_learning.sh` | learning mode: nothing blocked, observed domains/IPs appended to policy |
| `09_dns_strict.sh` | dns-strict: resolved IPs land in kernel timeout sets, never-resolved IPs dropped (dns lane only) |
| `10_audit.sh` | audit (dry-run) enforcement: would-be-blocked traffic passes and reaches the dashboard as AUDIT (https lane only) |
| `11_resources.sh` | coarse CPU and memory guardrails after modest allowed/blocked traffic |
| `12_load.sh` | concurrent allowed/blocked traffic, leak checks, latency, and stability under load |
| `13_dns_ip_allowlist.sh` | dns mode: a non-domain-allowlisted host pointing at an allowlisted IP resolves; the behaviour is off when the policy has no IPs (dns lane only) |
| `14_dashboard.sh` | production dashboard container with session auth, CORS/CSRF, static assets, SSE, API-key lifecycle, SQLite migrations/restart persistence, persistent logs, and fleet reconciliation (https lane only) |

Individual phase scripts assume the stack is already up, though mode-specific
phases may recreate the g0efilter container with different environment flags.
Shared helpers live in `lib.sh`.

The resource guardrail thresholds are intentionally conservative and can be
overridden with `E2E_MAX_MEMORY_MIB`, `E2E_MAX_MEMORY_GROWTH_MIB`,
`E2E_MAX_IDLE_CPU_PERCENT`, and `E2E_CPU_SAMPLE_SECONDS`.
