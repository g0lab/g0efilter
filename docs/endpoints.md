# Dashboard HTTP endpoints

The dashboard API has three authentication realms.

## Auth realms

| Realm | How a request authenticates | Used by |
| --- | --- | --- |
| **public** | none | health checks, login page, hashed UI assets |
| **machine** | `X-Api-Key: <key>` (see [API keys](configuration.md#api-keys)) | g0efilter instances |
| **UI** | session cookie, proxy header, bearer JWT, or no auth, based on `AUTH_MODE` | browser dashboard |

Successful responses are JSON; errors may be plain text. UI mutations are
CSRF-checked. CORS is off unless configured. Session-mode UI routes also accept
`X-Api-Key` for scripts.

## Public

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/health` | liveness; always 200 |
| `GET`/`HEAD` | `/login.html`, `/favicon.ico` | login page + icon |
| `GET`/`HEAD` | `/assets/*` | hashed JS/CSS bundles |

## Authentication (session mode)

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/v1/auth/login` | form login; per-IP rate-limited + CSRF-checked. Sets the session cookie |
| `POST` | `/api/v1/auth/logout` | authenticated + CSRF-checked; revokes the session |
| `GET` | `/api/v1/auth/me` | current principal, or 401 |

With no configured hash or existing user, session mode prints a generated admin
password once as `dashboard.bootstrap_admin`. Recover a password with
`g0efilter-dashboard reset-password [username]`; this requires persistent
storage.

## Machine realm (`X-Api-Key`)

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/unblocks` | instance polls for pending unblock requests |
| `POST` | `/api/v1/unblocks/ack` | instance acknowledges a processed unblock |
| `POST` | `/api/v1/logs` | log ingestion (rate-limited, JSON; accepts one object or an array) |
| `POST` | `/api/v1/sync` | fleet reconcile - only when `FLEET_ENABLED=true` (see below) |

## Human / UI realm

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/config` | UI config (feature flags such as `fleet_enabled`) |
| `GET` | `/api/v1/logs` | recent traffic logs (query: `q`, `since`, `limit`) - **sensitive** |
| `GET` | `/api/v1/logs/browse` | paginated search across stored logs - **sensitive** |
| `GET` | `/api/v1/aggregates` | server-side traffic totals (query: `range`, default `24h`; `q` filters host/IP) - **sensitive** |
| `GET` | `/api/v1/events` | UI-authenticated SSE live traffic stream - **sensitive** |
| `DELETE` | `/api/v1/logs` | clears all logs - **sensitive, destructive** |
| `POST` | `/api/v1/unblocks` | queue an unblock (firewall policy change) - **sensitive** |
| `GET` | `/api/v1/unblocks/status` | pending + completed unblocks |
| `GET` | `/api/v1/apikeys` | list API keys (metadata only; never the secret) |
| `POST` | `/api/v1/apikeys` | mint a key; plaintext returned **once** |
| `DELETE` | `/api/v1/apikeys/:id` | revoke a key |

## Fleet

These endpoints are available only when `FLEET_ENABLED=true` and require
persistent storage.

Admin (UI realm):

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/fleet/instances` | list instances + resolved group/sync state |
| `DELETE` | `/api/v1/fleet/instances/:id` | remove an instance |
| `PUT` | `/api/v1/fleet/instances/:id/group` | assign/clear group (`{"group_id":"..."}`) |
| `PUT` | `/api/v1/fleet/instances/:id/policy` | set/clear per-instance policy override |
| `GET` | `/api/v1/fleet/groups` | list groups |
| `POST` | `/api/v1/fleet/groups` | create a group (`{"name":"..."}`) |
| `DELETE` | `/api/v1/fleet/groups/:id` | delete a group |
| `PUT` | `/api/v1/fleet/groups/:id/policy` | set group policy + `filter_mode` (`https`/`dns`/`dns-strict`) |

Instance (machine realm) - `POST /api/v1/sync`:

```jsonc
// request
{ "hostname": "runner-1", "filter_mode": "https", "version": "v1.2.3", "config_hash": "..." }
// response
{ "managed": true, "changed": true, "config_hash": "...", "policy": "...", "filter_mode": "https" }
```

- `managed: false`: keep the local policy.
- `changed: true`: apply the returned policy and filter mode.
- `changed: false`: the reported `config_hash` is current.
- `?wait=<duration>` enables long-polling for up to 30 seconds.

## Static UI (catch-all)

`GET /` and unmatched non-API paths serve the UI behind its configured
authentication. The login page and assets remain public.
