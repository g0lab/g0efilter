# Configuration

## Environment variables

### g0efilter

| Variable | Description | Default |
| --- | --- | --- |
| `FILTER_MODE` | `https`, `dns`, or `dns-strict` | `https` |
| `POLICY_PATH` | Policy file. If unset, also checks `/app/policy/policy.yaml`. Never auto-created | `/app/policy.yaml` |
| `DEFAULT_ACTION` | `deny` (allowlist) or `allow` (denylist). Policy file `default_action` wins when set | `deny` |
| `ENFORCE` | `block` or `audit` (dry-run: log would-be blocks, allow traffic) | `block` |
| `LEARNING_MODE` | `true` to observe without blocking and auto-append seen domains/IPs to the policy | `false` |
| `ALLOWLIST_IPS` | Comma-separated allowed IPs/CIDRs (takes precedence over policy file) | unset |
| `ALLOWLIST_DOMAINS` | Comma-separated allowed domains (exact/wildcard/regex) | unset |
| `DENYLIST_IPS` | Comma-separated denied IPs/CIDRs (with `DEFAULT_ACTION=allow`) | unset |
| `DENYLIST_DOMAINS` | Comma-separated denied domains (with `DEFAULT_ACTION=allow`) | unset |
| `HTTP_PORT` | Local HTTP proxy port | `65080` |
| `HTTPS_PORT` | Local HTTPS proxy port | `65443` |
| `DNS_PORT` | Local DNS proxy port | `65053` |
| `DNS_UPSTREAMS` | Upstream DNS servers (comma-separated). Set this to cluster DNS in Kubernetes `dns` modes | `127.0.0.11:53` (Docker) |
| `DNS_HARDENING` | Anti-exfil checks in the DNS proxy: qname/label length caps, NULL and bulky-TXT answer rejection, per-source rate limiting | `true` |
| `DNS_RATE_QPS` | Sustained queries/sec. Redirected workloads share one budget | `50` |
| `DNS_RATE_BURST` | Hardening rate limiter: burst allowance per source | `100` |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `LOG_FILE` | Optional path for a persistent log file | unset |
| `DECISION_LOG_FILE` | Optional JSON Lines file containing `ALLOWED`, `BLOCKED`, and `AUDIT` decisions | unset |
| `BRIDGE_INTERFACES` | Comma-separated bridge names or patterns whose forwarded egress is filtered, for example `docker0,br-*`. Traffic that stays on a listed bridge is not filtered | unset |
| `HOSTNAME` | Identifies this instance in shipped logs | unset |
| `TENANT_ID` | Optional tenant identifier added to netfilter log events | unset |
| `DASHBOARD_HOST` | Dashboard URL for log shipping | unset |
| `DASHBOARD_API_KEY` | Active dashboard machine API key used for log shipping and remote unblock | unset |
| `DASHBOARD_QUEUE_SIZE` | Log buffer before shipping; drops when full | `1024` |
| `DASHBOARD_START_DELAY` | Delay before log shipping starts (`5s`, `1m`, ...) | `5s` |
| `ENABLE_REMOTE_UNBLOCK` | Poll dashboard for remote unblock requests | `false` |
| `UNBLOCK_POLL_INTERVAL` | Unblock poll interval | `10s` |
| `NOTIFICATION_URLS` | Whitespace-separated [shoutrrr](https://shoutrrr.nickfedor.com/) URLs for blocked-traffic alerts | unset |
| `NOTIFICATION_BACKOFF_SECONDS` | Duplicate-alert backoff | `60` |
| `NOTIFICATION_IGNORE_DOMAINS` | Blocks that should not alert (see below) | unset |
| `METRICS_ADDR` | Serve Prometheus metrics on this address, e.g. `:9095` (unset = disabled) | unset |
| `KUBE_EVENTS` | Record the first denials as Kubernetes Events on the pod (needs a mounted ServiceAccount token and `create` on `events`) | `false` |
| `KUBE_EVENTS_MAX` | Maximum distinct denials recorded as Events per pod | `10` |
| `NFLOG_BUFSIZE` | Netfilter log buffer size | `96` |
| `NFLOG_QTHRESH` | Netfilter log queue threshold | `50` |
| `MAX_CONNECTIONS` | Max concurrent connections per listener; excess is held via backpressure (`0` = unlimited) | `4096` |
| `CONN_MAX_LIFETIME_MS` | Max connection lifetime in ms (a single deadline, not an idle timeout; `0` = none) | `600000` |

The four allowlist/denylist variables suit short static lists. Because they are
comma-delimited, use a policy file for regexes containing commas and for dynamic
policy. Kubernetes packaging always uses a ConfigMap-backed file.

On Kubernetes these are set for you. `EgressPolicy`'s
[`spec.sidecar`](kubernetes.md#sidecar-options) and the library chart's values both
map onto this table. They omit settings that would replace the rendered policy:
the allowlist/denylist variables, `DEFAULT_ACTION`, and `LEARNING_MODE`.

#### Notifications

`NOTIFICATION_URLS` takes whitespace-separated
[shoutrrr](https://shoutrrr.nickfedor.com/) service URLs. Every service receives
each alert. A failure in one service does not stop the others.

```sh
NOTIFICATION_URLS="ntfy://ntfy.sh/my-topic telegram://BOT_TOKEN@telegram?chats=CHAT_ID"
```

Whitespace separates URLs, never commas: Telegram lists its `chats` with commas.
These URLs embed a token, so keep them in a secret store rather than in a
manifest.

Notification HTTP traffic and its hostname lookup bypass the filter. The `smtp`
and `mqtt` services do not use that HTTP client, so their destinations must be
allowed by the policy.

`NOTIFICATION_IGNORE_DOMAINS` is a comma-separated list of blocks that should
not alert. The block is still enforced and logged.

| Entry | Matches |
| --- | --- |
| `example.com` | that destination |
| `*.example.com` | subdomains, not the base domain |
| `10.0.0.0/8`, `1.2.3.4` | destinations in the prefix or at the address |
| `multicast`, `loopback`, `link-local`, `private`, `unspecified` | destinations in that address class |
| `local` | any of the five classes above |
| `public` | anything `local` does not match |
| `component:dns` | every block reported by that component |
| `ip-only` | blocks with no hostname, such as raw nflog verdicts |

`local` and `ip-only` can hide routine local traffic such as IPv6 neighbour
discovery on `ff02::` addresses.

#### Privileges

The agent starts and stays at uid/gid 65534. It needs only `NET_ADMIN`:

```yaml
cap_drop: [ALL]
cap_add: [NET_ADMIN]
```

The image sets `NET_ADMIN` as a file capability on `/app/g0efilter` and `nft`.
Both binaries need it because an executed child does not inherit the parent's
effective capabilities.

The container must still receive `NET_ADMIN` in its bounding set. Without it the
kernel fails closed with `exec /app/g0efilter: operation not permitted`.

`read_only: true`, `no-new-privileges` and Kubernetes'
`allowPrivilegeEscalation: false` are all supported and recommended. None of them
interfere with file capabilities.

Pod Security `baseline` excludes `NET_ADMIN`. A namespace that runs filtered
pods therefore needs the `privileged` label.

`g0efilter policy [path]` prints the active policy as a Kubernetes ConfigMap,
validating it first. `POLICY_CONFIGMAP` and `POD_NAMESPACE` set the emitted name and
namespace. The summary goes to stderr so stdout can be piped into `kubectl apply`.

To check a deployment's privileges without starting the filter:

```sh
docker run --rm --cap-drop=ALL --cap-add=NET_ADMIN docker.io/g0lab/g0efilter caps
kubectl exec <pod> -c g0efilter -- /app/g0efilter caps
```

It checks the capability state and `nft` netlink access, exiting non-zero with a
remediation hint on failure.

The dashboard image runs as uid 65532; its `/app/data` volume must be writable by
that user. The supplied Compose example handles this.

### g0efilter-dashboard

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | Listen address/port for UI and API | `:8081` |
| `API_KEY` | Machine API key. Generated and printed once when the key store is empty | unset |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `BUFFER_SIZE` | In-memory event buffer; oldest dropped when full | `5000` |
| `READ_LIMIT` | Max events per API request | `5000` |
| `SSE_RETRY_MS` | SSE client retry interval (ms) | `2000` |
| `WRITE_TIMEOUT` | HTTP write timeout in seconds (0 = none, recommended for SSE) | `0` |
| `RATE_RPS` | Rate limit, requests per second | `50` |
| `RATE_BURST` | Rate limit burst | `100` |
| `AUTH_MODE` | Web UI auth: `session` (built-in login), `none` (reverse proxy only), `forward` (trust proxy header), `jwt` (validate bearer token) | `session` |
| `ADMIN_USERNAME` | Login user for `session` mode | `admin` |
| `ADMIN_PASSWORD_HASH` | bcrypt admin hash. If absent, generates and prints a password once | unset |
| `SESSION_TTL` | Session lifetime (Go duration, e.g. `24h`) | `24h` |
| `COOKIE_SECURE` | Mark the session cookie `Secure` (HTTPS-only; localhost exempt). Set `false` only for plain-HTTP trials | `true` |
| `FORWARD_AUTH_HEADER` | Identity header trusted in `forward` mode | `X-Forwarded-User` |
| `JWT_SECRET` / `JWT_PUBLIC_KEY` / `JWKS_URL` | `jwt` mode key source (exactly one): HS256 secret, asymmetric PEM (inline or `@/path`), or an OIDC JWKS endpoint | unset |
| `JWT_USERNAME_CLAIM` | Claim used as the principal in `jwt` mode | `sub` |
| `JWT_ISSUER` / `JWT_AUDIENCE` | Optional `iss` / `aud` values required in `jwt` mode | unset |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the API (credentials enabled; `*` not allowed). Empty = same-origin only | unset |
| `DB_PATH` | SQLite file for dashboard state. Mount `/app/data` as a writable volume | `/app/data/dashboard.db` |
| `EPHEMERAL` | Keep all dashboard state in memory and reset it on restart | `false` |
| `LOG_RETENTION` | Target persisted log rows. Pruning runs every 256 inserts, so the count may briefly exceed this value | `100000` |
| `FLEET_ENABLED` | Enable fleet management (requires persistent storage) | `false` |

#### Dashboard authentication

`AUTH_MODE=session` protects the UI with a login and server-side sessions.

Set `ADMIN_PASSWORD_HASH` to a bcrypt hash:

```sh
docker run --rm -i docker.io/g0lab/g0efilter-dashboard:v0 hash-password
```

If no hash or admin user exists, the dashboard generates a password and prints
it once as `dashboard.bootstrap_admin`.

Reset a lost password with:

```sh
docker run --rm -v g0efilter-dashboard-data:/app/data \
  docker.io/g0lab/g0efilter-dashboard:v0 reset-password
```

The optional final argument is a username. `ADMIN_PASSWORD_HASH` overrides a
stored reset. Ephemeral mode resets credentials unless a hash is configured.

#### API keys

Machine endpoints use `X-Api-Key`. Set `API_KEY` to seed the first key. If the
key store is empty, the dashboard generates a key and prints it once as
`dashboard.bootstrap_api_key`.

Copy an active key to each agent's `DASHBOARD_API_KEY`. Create or revoke keys in
the UI or through `/api/v1/apikeys`. Ephemeral mode resets keys on restart.

#### Other authentication modes

- `none`: no UI authentication; use only behind an authenticating proxy.
- `forward`: trust the proxy identity in `FORWARD_AUTH_HEADER`.
- `jwt`: validate a bearer token or `jwt` cookie.

JWT mode requires exactly one of `JWT_SECRET`, `JWT_PUBLIC_KEY`, or `JWKS_URL`.
It validates signatures and time claims; issuer, audience, and username-claim
settings add further checks. Invalid key configuration fails startup.

#### CORS

The API is same-origin by default. Set `CORS_ALLOWED_ORIGINS` to a comma-separated
list for other browser origins. `*` is not allowed because requests include
credentials.

#### Fleet management (optional)

Set `FLEET_ENABLED=true` to enable fleet management. It requires persistent
storage. Clients reconcile through `POST /api/v1/sync`. The g0efilter agent does
not include a sync client.

The dashboard resolves policy from an instance override or its group. Manage
both in the **Fleet** tab. See [fleet endpoints](endpoints.md#fleet) for the
protocol.

#### Persistent logs

SQLite stores dashboard state and traffic logs. `LOG_RETENTION` sets the target
row count. The dashboard prunes every 256 inserts. Set `EPHEMERAL=true` to keep
state in memory and reset it on restart. Fleet management is unavailable in
ephemeral mode.
