# Configuration

## Environment variables

### g0efilter

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
| `HTTP_PORT` | Local HTTP proxy port | `65080` |
| `HTTPS_PORT` | Local HTTPS proxy port | `65443` |
| `DNS_PORT` | Local DNS proxy port | `65053` |
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
| `MAX_CONNECTIONS` | Max concurrent connections per listener; excess is held via backpressure (`0` = unlimited) | `4096` |
| `CONN_MAX_LIFETIME_MS` | Max connection lifetime in ms (a single deadline, not an idle timeout; `0` = none) | `600000` |
| `PUID` | Drop to this uid at startup (`0` = run as root) | `65534` (nobody) |
| `PGID` | Drop to this gid at startup | `65534` |

#### Running as a non-root user

The g0efilter container runs as a non-root user (`nobody`, uid 65534) by default.
Its entrypoint starts as root, hands the writable dirs (`/app/policy`, `/app/data`)
to the runtime user, then drops privileges - keeping `NET_ADMIN` as an
*ambient* capability so nftables and the SO_MARK dialer keep working. The binary
stays root-owned and read-only.

- Override the uid/gid with `PUID`/`PGID` (e.g. to match a host user that edits the
  policy file). Set `PUID=0` to run as root.
- `NET_ADMIN` is required at runtime (nftables + the SO_MARK dialer). Without it the
  container exits on startup rather than run with filtering disabled.
- The privilege drop additionally needs `SETUID`, `SETGID` (switch user) and `CHOWN`
  (hand over the writable dirs) *at startup*. These are not retained by the running
  process; if they are missing the entrypoint warns and stays root.
- Compatible with `read_only: true` and `no-new-privileges` (the numeric uid needs
  no `/etc/passwd` entry, and ambient caps survive `no-new-privileges`).

The g0efilter-dashboard image already runs non-root (`distroless` nonroot, uid
65532); its data volume just needs matching ownership (the compose examples chown
it once via an init container).

### g0efilter-dashboard

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | Listen address/port for UI and API | `:8081` |
| `API_KEY` | Machine API key. Generated and logged when the key store is empty | unset |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `BUFFER_SIZE` | In-memory event buffer; oldest dropped when full | `5000` |
| `READ_LIMIT` | Max events per API request | `5000` |
| `SSE_RETRY_MS` | SSE client retry interval (ms) | `2000` |
| `WRITE_TIMEOUT` | HTTP write timeout in seconds (0 = none, recommended for SSE) | `0` |
| `RATE_RPS` | Rate limit, requests per second | `50` |
| `RATE_BURST` | Rate limit burst | `100` |
| `AUTH_MODE` | Web UI auth: `session` (built-in login), `none` (reverse proxy only), `forward` (trust proxy header), `jwt` (validate bearer token) | `session` |
| `ADMIN_USERNAME` | Login user for `session` mode | `admin` |
| `ADMIN_PASSWORD_HASH` | bcrypt hash for the admin login; generate with `g0efilter-dashboard hash-password`. Optional in `session` mode - if unset and no admin user exists yet, a random password is auto-generated and logged once at startup | unset |
| `SESSION_TTL` | Session lifetime (Go duration, e.g. `24h`) | `24h` |
| `COOKIE_SECURE` | Mark the session cookie `Secure` (HTTPS-only; localhost exempt). Set `false` only for plain-HTTP trials | `true` |
| `FORWARD_AUTH_HEADER` | Identity header trusted in `forward` mode | `X-Forwarded-User` |
| `JWT_SECRET` / `JWT_PUBLIC_KEY` / `JWKS_URL` | `jwt` mode key source (exactly one): HS256 secret, asymmetric PEM (inline or `@/path`), or an OIDC JWKS endpoint | unset |
| `JWT_USERNAME_CLAIM` | Claim used as the principal in `jwt` mode | `sub` |
| `JWT_ISSUER` / `JWT_AUDIENCE` | Optional `iss` / `aud` values required in `jwt` mode | unset |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the API (credentials enabled; `*` not allowed). Empty = same-origin only | unset |
| `DB_PATH` | SQLite file for dashboard state. Mount `/app/data` as a writable volume | `/app/data/dashboard.db` |
| `EPHEMERAL` | Keep all dashboard state in memory and reset it on restart | `false` |
| `LOG_RETENTION` | Max persisted log rows before oldest are pruned | `100000` |
| `FLEET_ENABLED` | Enable fleet management (requires persistent storage) | `false` |

#### Dashboard authentication

`AUTH_MODE=session` (the default) serves a login form and protects all UI
endpoints (logs, live stream, unblocks, config) with server-side sessions.

The admin login is bootstrapped one of three ways:

- Set `ADMIN_PASSWORD_HASH` to a bcrypt hash you generate yourself:

  ```sh
  # generate the bcrypt hash for ADMIN_PASSWORD_HASH (reads one line from stdin)
  docker run --rm -i docker.io/g0lab/g0efilter-dashboard:latest hash-password
  ```

- Leave `ADMIN_PASSWORD_HASH` unset: on first startup with no existing admin
  user, a strong random password is generated and printed **once** (look for
  `dashboard.bootstrap_admin` in the container output). Log in and
  set your own hash, or rotate it with `reset-password`.
- Rotate a lost password, which prints a new one:

  ```sh
  # reset-password [username]; defaults to ADMIN_USERNAME (else "admin")
  docker run --rm -v g0efilter-dashboard-data:/app/data \
    docker.io/g0lab/g0efilter-dashboard:latest reset-password
  ```

  An existing `ADMIN_PASSWORD_HASH` overrides the reset on the next startup.

With `EPHEMERAL=true`, users live in memory, so a fresh random password is
generated on every restart unless `ADMIN_PASSWORD_HASH` is set.

### API key management

Machine endpoints authenticate with `X-Api-Key`. A supplied `API_KEY` is stored
as the initial key. If it is unset and the key store is empty, the dashboard
generates one and prints it once as `dashboard.bootstrap_api_key`. Copy that key
to each agent's `DASHBOARD_API_KEY`. The accompanying structured event contains
no secret.

Create and revoke keys in the dashboard or through `/api/v1/apikeys`. The
dashboard still starts with no active keys, but ingestion is unavailable until
an administrator creates one. With `EPHEMERAL=true`, keys reset on every restart.

Use `AUTH_MODE=none` to keep the pre-auth behavior behind Traefik/nginx, or
`AUTH_MODE=forward` behind an authenticating proxy (oauth2-proxy, Authelia)
that sets `FORWARD_AUTH_HEADER`.

`AUTH_MODE=jwt` validates a bearer token (`Authorization: Bearer …` or a `jwt`
cookie) for SSO/OIDC. Configure exactly one key source - `JWT_SECRET` (HS256),
`JWT_PUBLIC_KEY` (RS256/ES256 PEM, inline or `@/path/to/key.pem`), or `JWKS_URL`
(fetched and cached from your IdP). Signature and expiry are always checked; set
`JWT_ISSUER`/`JWT_AUDIENCE` to also require `iss`/`aud`, and `JWT_USERNAME_CLAIM`
to pick the principal claim (default `sub`). Startup fails closed on a missing,
ambiguous, or unreachable key source.

#### CORS

By default the API is same-origin only. To allow a browser app on another
origin (e.g. a separately hosted UI), set `CORS_ALLOWED_ORIGINS` to a
comma-separated list. Credentials are enabled, so origins must be listed
explicitly - the `*` wildcard is rejected.

#### Fleet management (optional)

Set `FLEET_ENABLED=true` to manage g0efilter instances
from the dashboard. The dashboard-side API accepts bounded long-poll
reconciliation at `POST /api/v1/sync?wait=30s`, reporting instance state and
returning desired policy + filter mode. The planned managed instance client will
opt in with `MANAGED=true` + `DASHBOARD_URL`; it has not landed yet. The dashboard
resolves desired config per instance as
**instance override → group → unmanaged**; the `config_hash` makes steady-state
responses a tiny no-op, shipping policy only on change. Manage groups, policies
and instance assignments from the **Fleet** tab in the UI. Default off - remote
control of an egress filter is sensitive, so it is opt-in on both ends. See the
[dashboard control-plane plan](dashboard-control-plane.md) for transport choices
and migration status.

#### Persistent logs

Traffic logs and dashboard state are stored in SQLite by default. `LOG_RETENTION`
limits stored rows. Set `EPHEMERAL=true` to use an in-memory ring buffer instead;
all dashboard state then resets on restart and fleet management is unavailable.
The Aggregates page queries retained SQLite history directly, using the last 24
hours by default; operators can select shorter windows or all retained history.
