[![docker pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter.svg?label=docker%20pulls)](https://hub.docker.com/r/g0lab/g0efilter)
[![g0efilter CI](https://github.com/g0lab/g0efilter/actions/workflows/ci.yaml/badge.svg)](https://github.com/g0lab/g0efilter/actions/workflows/ci.yaml)
[![g0efilter Tests](https://github.com/g0lab/g0efilter/actions/workflows/test.yaml/badge.svg)](https://github.com/g0lab/g0efilter/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/g0lab/g0efilter/graph/badge.svg?token=owO27TfE79)](https://codecov.io/gh/g0lab/g0efilter)

> [!NOTE]
> Portions of this project were developed with the assistance of AI tools.

> [!WARNING]
> g0efilter is in active development and its configuration may change often.

g0efilter is a lightweight container that filters outbound (egress) traffic from attached container workloads. Run it alongside your workloads, attach them with `network_mode: "service:g0efilter"`, and enforce an IP and domain policy without terminating TLS.

### Features

- **Egress filtering** by IP/CIDR and domain, default-deny with an allowlist
- **Flexible domain patterns**: exact names, wildcards anywhere (`*.example.com`, `bucket.*.r2.example.com`), and regex (`/cache-[0-9]+\.example\.com/`)
- **Three filter modes**: `https` (SNI/Host inspection), `dns` (resolution filtering), `dns-strict` (resolution filtering plus kernel connection-time enforcement)
- **Default-allow (denylist) mode**: allow everything except listed domains/IPs
- **Learning mode**: observe without blocking and auto-build the allowlist
- **Audit mode**: dry-run a policy; would-be blocks are logged, nothing breaks
- **Process attribution**: flow logs can carry the owning PID/command (opt-in)
- **Live policy reloading**, real-time dashboard, remote unblock, Gotify notifications

### Quick start

Create a policy directory:

```sh
mkdir -p policy
```

Add `policy/policy.yaml`:

```yaml
allowlist:
  ips:
    - '1.1.1.1'
  domains:
    - 'github.com'
    - '*.alpinelinux.org'
```

Run g0efilter and attach a workload to its network namespace:

```yaml
services:
  g0efilter:
    image: docker.io/g0lab/g0efilter:latest
    volumes:
      - ./policy/:/app/policy/
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges

  example-container:
    image: docker.io/alpine/curl:latest
    command: sh -c "sleep infinity"
    network_mode: "service:g0efilter"
```

See [examples](https://github.com/g0lab/g0efilter/tree/main/examples) for ready-to-run compose files and policies.

### How it works

Attached containers share g0efilter's network namespace. Traffic to allowlisted IPs/CIDRs passes through directly; everything else is handled by the selected `FILTER_MODE`.

| Mode | Checks domains at | Blocks hardcoded IPs? | Best for |
| --- | --- | ---: | --- |
| `https` | Connection time via TLS SNI / HTTP Host inspection | Yes, unless IP allowlisted | Web-heavy workloads needing precise domain control |
| `dns` | DNS resolution time | No | Lightweight broad filtering |
| `dns-strict` | DNS plus kernel connection-time enforcement | Yes | Strong default-deny egress control |

See [docs/modes.md](docs/modes.md) for detailed flow diagrams and mode-specific limits.

> [!NOTE]
> Attached containers must not bind to ports used by g0efilter: `HTTP_PORT` (8080), `HTTPS_PORT` (8443), and `DNS_PORT` (53) in dns modes.

### Policy

```yaml
allowlist:
  ips:
    - '1.1.1.1'
    - '192.168.0.0/16'
  domains:
    - 'github.com'                                 # exact
    - '*.alpinelinux.org'                          # wildcard, any subdomain level
    - 'bucket.*.r2.cloudflarestorage.com'          # wildcard works mid-name too
    - '/cache-[0-9]+\.example\.com/'              # regex (single-quote it in YAML)
```

Each `*` matches one or more characters including dots. Regex entries are slash-delimited, matched case-insensitively against the whole hostname (anchoring is automatic), and compiled with Go's linear-time RE2 engine. Ready-made example policies live in [examples/policy/](https://github.com/g0lab/g0efilter/tree/main/examples/policy).

The policy file live-reloads: edits apply without restarting the container. Mount the policy *directory*, not the single file, or editors that use atomic save will silently break reloads:

```yaml
volumes:
  - ./policy/:/app/policy/   # correct
# NOT: - ./policy.yaml:/app/policy.yaml
```

Environment variables (`ALLOWLIST_IPS`, `ALLOWLIST_DOMAINS`, ...) can replace the policy file and take precedence when set. See [docs/policy.md](docs/policy.md) for policy modes and [docs/configuration.md](docs/configuration.md) for environment variables.

### Common modes

Set `default_action: allow` in the policy file to invert the model: traffic passes unless it matches the `denylist`. Useful for containers that need broad internet access but should be kept away from analytics/telemetry endpoints or the LAN. An explicit allowlist match always overrides the denylist.

`LEARNING_MODE=true` runs g0efilter observe-only: nothing is blocked and every domain (or destination IP when no SNI/Host is present) not already covered is appended to the policy file. Run it for a representative period, prune the result, then switch back to enforcement.

`ENFORCE=audit` is a dry run for an existing policy: would-be-blocked traffic is allowed through and logged with the `AUDIT` action (visible in the dashboard), so you can preview a policy's impact before enforcing it. Unlike learning mode, nothing is written to the policy file.

`PROCESS_INFO=true` enriches flow logs with the owning process (`pid`, `process_name`, `cmdline`, `executable`), resolved via `/proc` and cached per flow. This requires g0efilter to share a PID namespace with the client processes (host deploy, `pid: host`, or `shareProcessNamespace: true`); in a plain network-only sidecar the fields degrade to `process_name=unknown`.

### GitHub Actions

g0efilter can filter egress from GitHub Actions runners. The action starts the g0efilter container with host networking, so all traffic from the job and later steps is inspected.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Filter egress
        uses: g0lab/g0efilter@v0
        with:
          egress-policy: block   # or 'audit' to log without blocking
          allowed-domains: |
            *.npmjs.org
            registry.npmjs.org

      - uses: actions/checkout@v7
```

See [docs/github-actions.md](docs/github-actions.md) for inputs, baseline allow rules, and runner limitations.

### Dashboard

The optional **g0efilter-dashboard** container serves a web UI on port 8081. Set `DASHBOARD_HOST` and `DASHBOARD_API_KEY` on g0efilter to ship logs to it.

![g0efilter-dashboard-example](https://raw.githubusercontent.com/g0lab/g0efilter/main/examples/images/g0efilter-dashboard-example.png)

Remote unblock lets administrators unblock domains/IPs from the dashboard UI. Instances poll for approved requests and apply them via live reload. It is disabled by default. To enable it, set `ENABLE_REMOTE_UNBLOCK=true` on g0efilter along with `DASHBOARD_HOST` and `DASHBOARD_API_KEY`. See [docs/remote-unblock.md](docs/remote-unblock.md) for setup, endpoints, and a Traefik example.

> [!WARNING]
> Do not enable remote unblock without protecting `POST /api/v1/unblocks` behind authentication middleware. Anyone who can reach that endpoint can modify your allowlist.

### Example docker-compose.yaml

```yaml
services:
  g0efilter:
    image: docker.io/g0lab/g0efilter:latest
    container_name: g0efilter
    volumes:
      - ./policy/:/app/policy/   # directory mount, see Policy section
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN                # required for nftables
    security_opt:
      - no-new-privileges
    ports:
      - 8081:8081                # dashboard (runs in the same netns)
    read_only: true
    restart: always
    env_file:
      - .env

  g0efilter-dashboard:
    image: docker.io/g0lab/g0efilter-dashboard:latest
    container_name: g0efilter-dashboard
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges
    read_only: true
    env_file:
      - .env.dashboard
    network_mode: "service:g0efilter"
    restart: always

  example-container:
    image: docker.io/alpine/curl:latest
    command: sh -c "sleep infinity"
    network_mode: "service:g0efilter"
```

### Documentation

- [Filter modes](docs/modes.md)
- [Policy](docs/policy.md)
- [Configuration and environment variables](docs/configuration.md)
- [GitHub Actions](docs/github-actions.md)
- [Remote unblock](docs/remote-unblock.md)

### Verifying container signatures

Images are signed with [Cosign](https://github.com/sigstore/cosign) keyless signing:

```bash
cosign verify g0lab/g0efilter:latest \
  --certificate-identity-regexp=https://github.com/g0lab/g0efilter \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  -o text
```

(Repeat with `g0lab/g0efilter-dashboard:latest` for the dashboard image.)

## License

MIT, see [LICENSE](LICENSE).
