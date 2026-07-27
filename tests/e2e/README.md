# End-to-end tests

Go tests driving real containers through Testcontainers. They need Docker with
the Compose plugin.

This directory is its own Go module. The Testcontainers dependency tree is large
and test-only, so it stays out of the module that ships the agent and dashboard.

## Running

```sh
cd tests/e2e
E2E_FILTER_MODE=https       go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns         go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns-strict  go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
```

Each run covers one filter mode; suites that do not apply to it skip. Full
coverage means all three, which is how CI runs them:

| Mode | Suites |
| --- | --- |
| `https` | shared phases, IPv6, learning, audit, resources, load, dashboard, images, IP port constraints |
| `dns` | shared phases, learning, resources, load, IP allowlist |
| `dns-strict` | dns-strict enforcement, IP allowlist, IP/domain port constraints, load |

The suite builds `g0efilter:test` and `g0efilter-dashboard:test` from the
repository source when they are missing, so a fresh clone needs no separate
step. It will not rebuild an existing image, so rebuild explicitly after
changing agent or dashboard code:

```sh
E2E_BUILD=force go test -count=1 -v -timeout=25m .
```

Always pass `-count=1`: these tests drive external container state and must
never be served from the test result cache. Keep `-parallel=1` for full runs so
container-heavy suites do not distort each other's resource and load checks.

Select individual suites with `-run`:

```sh
E2E_FILTER_MODE=dns-strict go test -count=1 -v -run '^TestPhase09DNSStrict$' .
E2E_FILTER_MODE=https      go test -count=1 -v -run '^TestPhase14Dashboard$' .
```

`internal/harness` holds the stack lifecycle, typed container exec, traffic
assertions, log parsing, the dashboard API client, nftables inspection and the
load driver. `compose.test.yaml` is the test stack: no fixed container names, an
ephemeral host port, and a per-stack policy directory, so stacks can run
concurrently.

## How assertions work

A blocked-traffic assertion requires the request to fail and g0efilter to record
a matching decision after it began. A failed request alone could be an unrelated
resolver, container or network failure.

Where a path records no verdict by design - plain dns mode accepts direct-IP
traffic in the kernel without logging it - use `AssertReachable` and
`AssertUnreachable`, and pair them with `AssertIPVerdict` where an nflog decision
does exist.

## Stack reuse

`harness.Shared` reuses interchangeable deployments and locks each stack to one
test at a time. Use `harness.StartStack` for tests that change stack-level state,
such as restarts, volume contents or container flags.

Each suite sets the policy it needs rather than inheriting the previous one's.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `E2E_FILTER_MODE` | `https` | `https`, `dns` or `dns-strict` |
| `E2E_BUILD` | `auto` | `auto` builds missing images, `force` always rebuilds, `never` skips |
| `E2E_LOG_TAIL` | `20` | Failure log tail; `0` dumps everything |
| `E2E_TESTCONTAINERS_LOG` | `0` | `1` prints Testcontainers lifecycle logs |
| `E2E_BROWSER` | `0` | `1` runs the Playwright smoke test |
| `G0EFILTER_IMAGE` | `g0efilter:test` | Agent image under test |
| `G0EFILTER_DASHBOARD_IMAGE` | `g0efilter-dashboard:test` | Dashboard image under test |
| `E2E_MAX_MEMORY_MIB` | `256` | Memory ceiling |
| `E2E_MAX_MEMORY_GROWTH_MIB` | `64` | Memory growth allowance |
| `E2E_MAX_IDLE_CPU_PERCENT` | `25` | Idle CPU ceiling |
| `LOAD_TOTAL` | `500` | Blocked requests in the load phase |
| `LOAD_TOTAL_HTTP` | `LOAD_TOTAL / 2` | Blocked HTTP requests |
| `LOAD_CONCURRENCY` | `50` | Load concurrency |
| `LOAD_ALLOWED` | `25` | Allowed requests in the mixed-load check |
| `LOAD_MAX_TIME` | `8` | Per-request timeout in seconds |
| `LOAD_MAX_LATENCY_MS` | `2000` | Median blocked-latency ceiling |
| `LOAD_MIN_ALLOWED_PERCENT` | `100` | Min % of the `LOAD_ALLOWED` requests that must connect while blocked traffic floods alongside them: every one of the default 25. Lower it if upstream flakiness proves noisy, since this measures the upstream as well as the filter. The filter's own decision is checked separately, by requiring no `BLOCKED` verdict for an allowed URL |
| `LOAD_RECOVERY_PAUSE` | `4s` | Pause before the mixed check so the DNS rate limiter refills, otherwise it, not the filter, decides the result |
| `LOAD_ALLOWED_URLS` | `https://github.com https://1.1.1.1` | Space-separated URLs used round-robin for allowed traffic, so one degraded upstream cannot sink the success rate. Both are covered by the baseline policy |
| `LOAD_BLOCKED_URL` | `https://google.com` | URL used for blocked HTTPS traffic |
| `LOAD_BLOCKED_URL_HTTP` | `http://google.com` | URL used for blocked HTTP traffic |
| `E2E_LOAD_MAX_MEMORY_MIB` | `384` | Memory ceiling after the load phase |
| `E2E_CPU_SAMPLE_WINDOW` | `6s` | Sampling window for the idle-CPU check |

For the browser smoke test:

```sh
cd dashboard/ui
pnpm install --frozen-lockfile
pnpm exec playwright install --with-deps chromium
cd ../../tests/e2e
E2E_FILTER_MODE=https E2E_BROWSER=1 go test -count=1 -v -run '^TestPhase14Dashboard$' .
```
