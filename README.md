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
- **Flexible domain patterns**: exact names, wildcards anywhere (`*.example.com`, `bucket.*.r2.example.com`), and regex (`/^cache-[0-9]+\.example\.com$/`)
- **Three filter modes**: `https` (SNI/Host inspection), `dns` (resolution filtering), `dns-strict` (resolution filtering plus kernel connection-time enforcement)
- **Default-allow (denylist) mode**: allow everything except listed domains/IPs
- **Learning mode**: observe without blocking and auto-build the allowlist
- **Audit mode**: dry-run a policy; would-be blocks are logged, nothing breaks
- **Process attribution**: flow logs can carry the owning PID/command (opt-in)
- **Live policy reloading**, real-time dashboard, remote unblock, Gotify notifications

### Quick start

See [examples](https://github.com/g0lab/g0efilter/tree/main/examples) for ready-to-run compose files and policies.

### How it works

Attached containers share g0efilter's network namespace. Traffic to allowlisted IPs/CIDRs passes through directly; everything else is handled by the selected `FILTER_MODE`:

<details>
<summary><b>https mode (default): TLS SNI / HTTP Host inspection</b></summary>

Outbound traffic on ports 80/443 is redirected by nftables to local proxy services inside g0efilter. The proxies read the HTTP `Host` header (port 80) or the TLS SNI from the ClientHello (port 443, without terminating TLS) and check it against the policy. Allowed connections are spliced through to the original destination at kernel speed; blocked connections are reset. Traffic on other ports is dropped unless the destination IP is allowlisted.

```text
Start
|
+- Destination IP in allowlist? -- Yes -> ALLOW (no redirect)
|
+- Connection already established? -- Yes -> ALLOW
|
+- Destination port 80/443? -- No -> BLOCK
|
+- Redirect to local proxy, extract Host header / SNI
|
+- Domain matches policy? -- Yes -> FORWARD to original destination
|                          -- No  -> DROP (connection reset)
|
+- LOG decision -> dashboard (if enabled)
```

Strengths: precise per-connection domain checks, works with CDNs and changing IPs.
Limits: domain filtering applies to ports 80/443 only; a client that sends no SNI is blocked (default-deny).

</details>

<details>
<summary><b>dns mode: resolution filtering</b></summary>

All DNS (UDP/TCP port 53) is redirected to an internal DNS proxy. Allowed domains resolve normally through the upstream resolver; non-allowlisted A/AAAA queries are sinkholed to 0.0.0.0/:: and other blocked query types get NXDOMAIN.

```text
Start
|
+- DNS query to port 53? -- No -> PASS (no domain check)
|
+- Redirect to local DNS proxy
|
+- Domain matches policy? -- Yes -> FORWARD to upstream resolver
|                          -- No  -> SINKHOLE A/AAAA or NXDOMAIN
|
+- LOG decision -> dashboard (if enabled)
```

Strengths: covers every protocol and port, cheapest data path (no proxying of the traffic itself).
Limits: enforcement happens at resolution only. A process that connects to a hardcoded IP, uses DNS-over-HTTPS, or replays a cached answer bypasses filtering entirely. Use `dns-strict` to close that gap.

</details>

<details>
<summary><b>dns-strict mode: resolution filtering plus connection-time enforcement</b></summary>

Everything dns mode does, plus: when an allowed domain resolves, the proxy pushes the answer's A/AAAA addresses into a kernel nftables set with a TTL-bounded timeout (60s floor, 24h cap), before the client sees the answer. The filter chain is default-drop, so connections to any IP that was never resolved through the proxy (hardcoded IPs, DoH, cached answers) are dropped.

```text
Start
|
+- Destination IP in allowlist/resolved set? -- Yes -> ALLOW
|
+- DNS query to port 53? -- Yes -> Redirect to DNS proxy
|      |
|      +- Domain matches policy? -- Yes -> Resolve, add answer IPs, return answer
|      |                          -- No  -> SINKHOLE A/AAAA or NXDOMAIN
|
+- Connection already established? -- Yes -> ALLOW
|
+- BLOCK
|
+- LOG decision -> dashboard (if enabled)
```

- Enforcement covers all ports and both IPv4/IPv6, entirely in the kernel
- Entries expire with the DNS TTL; established connections survive expiry via conntrack
- Resolved entries are flushed on policy reload and repopulate on the next resolution
- Requires `default_action: deny`; under default-allow or learning mode it degrades to plain dns mode with a warning

</details>

> [!NOTE]
> Attached containers must not bind to ports used by g0efilter: `HTTP_PORT` (8080), `HTTPS_PORT` (8443), and `DNS_PORT` (53) in dns modes.

### Policy

```yaml
allowlist:
  ips:
    - "1.1.1.1"
    - "192.168.0.0/16"
  domains:
    - "github.com"                                 # exact
    - "*.alpinelinux.org"                          # wildcard, any subdomain level
    - "bucket.*.r2.cloudflarestorage.com"          # wildcard works mid-name too
    - '/^cache-[0-9]+\.example\.com$/'             # regex (single-quote it in YAML)
```

Each `*` matches one or more characters including dots. Regex entries are slash-delimited, matched case-insensitively against the whole hostname (anchoring is automatic), and compiled with Go's linear-time RE2 engine. Ready-made example policies live in [examples/policy/](https://github.com/g0lab/g0efilter/tree/main/examples/policy).

The policy file live-reloads: edits apply without restarting the container. Mount the policy *directory*, not the single file, or editors that use atomic save will silently break reloads:

```yaml
volumes:
  - ./policy/:/app/policy/   # correct
# NOT: - ./policy.yaml:/app/policy.yaml
```

Environment variables (`ALLOWLIST_IPS`, `ALLOWLIST_DOMAINS`, ...) can replace the policy file and take precedence when set.

### Default-allow (denylist) mode

Set `default_action: allow` in the policy file to invert the model: traffic passes unless it matches the `denylist`. Useful for containers that need broad internet access but should be kept away from analytics/telemetry endpoints or the LAN. An explicit allowlist match always overrides the denylist.

```yaml
default_action: allow
allowlist:
  domains:
    - "api.github.com"        # explicitly allow this host even though *.github.com is denylisted
denylist:
  ips:
    - "192.168.0.0/16"        # block LAN access
  domains:
    - "*.github.com"          # deny broad GitHub subdomains
    - "*.doubleclick.net"
    - "telemetry.example.com"
```

Because `default_action` lives in the policy file, flipping it is a live-reload edit. When it is `deny` (the default), the denylist is ignored.

### Learning mode

`LEARNING_MODE=true` runs g0efilter observe-only: nothing is blocked and every domain (or destination IP when no SNI/Host is present) not already covered is appended to the policy file. Run it for a representative period, prune the result, then switch back to enforcement.

### Audit mode

`ENFORCE=audit` is a dry run for an existing policy: would-be-blocked traffic is allowed through and logged with the `AUDIT` action (visible in the dashboard), so you can preview a policy's impact before enforcing it. Unlike learning mode, nothing is written to the policy file.

### Process attribution

`PROCESS_INFO=true` enriches flow logs with the owning process (`pid`, `process_name`, `cmdline`, `executable`), resolved via `/proc` and cached per flow. This requires g0efilter to share a PID namespace with the client processes (host deploy, `pid: host`, or `shareProcessNamespace: true`); in a plain network-only sidecar the fields degrade to `process_name=unknown`.

### GitHub Actions (CI egress filtering)

g0efilter can filter egress from GitHub Actions runners. The action starts the g0efilter container with host networking, so all traffic from the job (and later steps) is inspected, and adds a report of blocked/audited connections to the job summary.

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
      # ... the rest of the job runs behind the filter
```

| Input | Description | Default |
|-------|-------------|---------|
| `allowed-domains` | Newline-separated domains (wildcards and regex supported) | |
| `allowed-ips` | Newline-separated IPs/CIDRs | |
| `egress-policy` | `block` or `audit` | `block` |
| `mode` | `https` (SNI/Host inspection) or `dns` | `https` |
| `log-level` | g0efilter log level | `INFO` |
| `image` | Container image to run | matches the action's release tag, or `:latest` for branch refs |

GitHub's [documented runner communication domains](https://docs.github.com/actions/reference/runners/self-hosted-runners) (`github.com`, `api.github.com`, `*.actions.githubusercontent.com`, `codeload.github.com`, artifact/log storage, release downloads) and the runner's DNS resolvers are always allowed so the workflow itself keeps working. Package registries are **not** in the baseline - if a step pulls containers or packages, add the registry (`ghcr.io`, `*.pkg.github.com`, `registry.npmjs.org`, ...) to `allowed-domains`.

> [!NOTE]
> Limitations: GitHub-hosted Ubuntu runners only. Traffic from Docker containers started by later steps is filtered only when they use `--network host`; jobs that run inside a container (`container:`) are not supported. `egress-policy: audit` requires a g0efilter release with audit mode (newer than v0.5.13) - on older images it enforces `block`.

### Dashboard

The optional **g0efilter-dashboard** container serves a web UI on port 8081. Set `DASHBOARD_HOST` and `DASHBOARD_API_KEY` on g0efilter to ship logs to it.

![g0efilter-dashboard-example](https://raw.githubusercontent.com/g0lab/g0efilter/main/examples/images/g0efilter-dashboard-example.png)

### Environment variables

#### g0efilter

| Variable | Description | Default |
| --- | --- | --- |
| `FILTER_MODE` | `https`, `dns`, or `dns-strict` | `https` |
| `POLICY_PATH` | Path to policy file inside container. When unset, `/app/policy.yaml` is used if present, then `/app/policy/policy.yaml` (the directory-mount convention). The file is never auto-created. | `/app/policy.yaml` |
| `DEFAULT_ACTION` | `deny` (allowlist) or `allow` (denylist). Policy file `default_action` wins when set | `deny` |
| `ENFORCE` | `block` or `audit` (dry-run: log would-be blocks, allow traffic) | `block` |
| `LEARNING_MODE` | `true` to observe without blocking and auto-append seen domains/IPs to the policy | `false` |
| `PROCESS_INFO` | `true` to add pid/process fields to flow logs (needs shared PID namespace) | `false` |
| `ALLOWLIST_IPS` | Comma-separated allowed IPs/CIDRs (takes precedence over policy file) | unset |
| `ALLOWLIST_DOMAINS` | Comma-separated allowed domains (exact/wildcard/regex) | unset |
| `DENYLIST_IPS` | Comma-separated denied IPs/CIDRs (with `DEFAULT_ACTION=allow`) | unset |
| `DENYLIST_DOMAINS` | Comma-separated denied domains (with `DEFAULT_ACTION=allow`) | unset |
| `HTTP_PORT` | Local HTTP proxy port | `8080` |
| `HTTPS_PORT` | Local HTTPS proxy port | `8443` |
| `DNS_PORT` | DNS listen port | `53` |
| `DNS_UPSTREAMS` | Upstream DNS servers (comma-separated) | `127.0.0.11:53` |
| `DNS_HARDENING` | Anti-exfil checks in the DNS proxy: qname/label length caps, NULL and bulky-TXT answer rejection, per-source rate limiting | `true` |
| `DNS_RATE_QPS` | Hardening rate limiter: sustained queries/sec per source. All local traffic shares one source behind the NAT redirect, so this bounds the whole host | `50` |
| `DNS_RATE_BURST` | Hardening rate limiter: burst allowance per source | `100` |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `LOG_FILE` | Optional path for a persistent log file | unset |
| `HOSTNAME` | Identifies this instance in shipped logs | unset |
| `DASHBOARD_HOST` | Dashboard URL for log shipping | unset |
| `DASHBOARD_API_KEY` | Must match `API_KEY` on the dashboard | unset |
| `DASHBOARD_QUEUE_SIZE` | Log buffer before shipping; drops when full | `1024` |
| `DASHBOARD_START_DELAY` | Delay before log shipping starts (`5s`, `1m`, ...) | `5s` |
| `ENABLE_REMOTE_UNBLOCK` | Poll dashboard for remote unblock requests | `false` |
| `UNBLOCK_POLL_INTERVAL` | Unblock poll interval | `10s` |
| `NOTIFICATION_HOST` | Gotify server URL for blocked-traffic alerts | unset |
| `NOTIFICATION_KEY` | Gotify application key | unset |
| `NOTIFICATION_BACKOFF_SECONDS` | Duplicate-alert backoff | `60` |
| `NOTIFICATION_IGNORE_DOMAINS` | Domains to skip for notifications (wildcards ok) | unset |
| `NFLOG_BUFSIZE` | Netfilter log buffer size | `96` |
| `NFLOG_QTHRESH` | Netfilter log queue threshold | `50` |

> [!NOTE]
> Most hosts need no DNS source-port tuning. In DNS modes, upstream UDP forwards bind to `61000-64999` to avoid conntrack collisions with redirected client queries. If you widen `net.ipv4.ip_local_port_range` past `60999`, reserve that window with `net.ipv4.ip_local_reserved_ports`.

#### g0efilter-dashboard

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | Listen address/port for UI and API | `:8081` |
| `API_KEY` | Authenticates log ingestion from g0efilter | unset |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `BUFFER_SIZE` | In-memory event buffer; oldest dropped when full | `5000` |
| `READ_LIMIT` | Max events per API request | `5000` |
| `SSE_RETRY_MS` | SSE client retry interval (ms) | `2000` |
| `WRITE_TIMEOUT` | HTTP write timeout in seconds (0 = none, recommended for SSE) | `0` |
| `RATE_RPS` | Rate limit, requests per second | `50` |
| `RATE_BURST` | Rate limit burst | `100` |

### Remote unblock

Administrators can unblock domains/IPs from the dashboard UI; g0efilter instances poll for pending requests and update their policy files.

> [!WARNING]
> Disabled by default. Only enable behind authentication middleware: `POST /api/v1/unblocks` must be protected (Authelia, Authentik, PocketID, ...) or anyone reaching the dashboard can modify your allowlist.

<details>
<summary><b>API endpoints and example Traefik configuration</b></summary>

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | None | Health check |
| `POST /api/v1/logs` | API Key | Log ingestion from g0efilter |
| `GET /api/v1/unblocks?hostname=X` | API Key | Poll pending unblocks (g0efilter) |
| `POST /api/v1/unblocks/ack` | API Key | Acknowledge processed unblock (g0efilter) |
| `GET /` | Middleware | Dashboard web UI |
| `GET /api/v1/config` | Middleware | Server configuration for UI |
| `GET /api/v1/logs` | Middleware | Read logs |
| `GET /api/v1/events` | Middleware | Server-Sent Events stream |
| `DELETE /api/v1/logs` | Middleware | Clear logs |
| `POST /api/v1/unblocks` | Middleware | Create unblock request (UI) |
| `GET /api/v1/unblocks/status` | Middleware | Poll unblock status (UI) |

Two Traefik routers handle the different auth requirements: an ingest router (API-key endpoints, no SSO) and a dashboard router (everything else behind your auth middleware).

```yaml
http:
  routers:
    g0efilter-ingest-router:
      entryPoints:
        - websecure
      rule: "Host(`g0efilter.example.com`) && ((PathPrefix(`/api/v1/logs`) && Method(`POST`)) || PathPrefix(`/health`) || (Path(`/api/v1/unblocks`) && Method(`GET`) && QueryRegexp(`hostname`, `^.+$`)) || (Path(`/api/v1/unblocks/ack`) && Method(`POST`)))"
      service: g0efilter-dash-service
      middlewares:
        - security-headers
        - ratelimit
      tls:
        certResolver: letsencrypt

    g0efilter-dash-router:
      entryPoints:
        - websecure
      rule: "Host(`g0efilter.example.com`)"
      service: g0efilter-dash-service
      middlewares:
        - security-headers
        - ratelimit
        - auth-oidc  # your auth middleware
      tls:
        certResolver: letsencrypt

  services:
    g0efilter-dash-service:
      loadBalancer:
        servers:
          - url: "http://g0efilter-dashboard:8081"
```

</details>

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
