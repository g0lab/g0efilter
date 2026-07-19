# Dashboard HTTP endpoints

The `g0efilter-dashboard` server exposes a small HTTP API plus the embedded
Svelte UI. Routes fall into distinct **auth realms**; a request must satisfy the
realm of the route it hits.

## Auth realms

| Realm | How a request authenticates | Used by |
| --- | --- | --- |
| **public** | none | health checks, login page, hashed UI assets |
| **machine** | `X-Api-Key: <key>` (see [configuration.md](configuration.md)) | g0efilter instances |
| **session/UI** | session cookie (`AUTH_MODE=session`), proxy header (`forward`), bearer JWT (`jwt`), or open (`none`) - plus CSRF (Origin / `Sec-Fetch-Site`) on mutations | the browser dashboard |

All JSON responses are `application/json`. Mutating UI requests are CSRF-checked;
cross-site requests are rejected. CORS is off unless `CORS_ALLOWED_ORIGINS` is set
(and a wildcard `*` is rejected at startup).

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

Bootstrap: in `session` mode with no `ADMIN_PASSWORD_HASH` and no existing user,
the server auto-generates a random admin password and logs it **once** at startup.
Recover a lost password with `g0efilter-dashboard reset-password [username]`
(requires persistent storage).

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
| `GET` | `/api/v1/aggregates` | server-side traffic totals (query: `range`, default `24h`; `q` filters host/IP) - **sensitive** |
| `GET` | `/api/v1/events` | SSE live traffic stream (cookie-authenticated) - **sensitive** |
| `DELETE` | `/api/v1/logs` | clears all logs - **sensitive, destructive** |
| `POST` | `/api/v1/unblocks` | queue an unblock (firewall policy change) - **sensitive** |
| `GET` | `/api/v1/unblocks/status` | pending + completed unblocks |
| `GET` | `/api/v1/apikeys` | list API keys (metadata only; never the secret) |
| `POST` | `/api/v1/apikeys` | mint a key; plaintext returned **once** |
| `DELETE` | `/api/v1/apikeys/:id` | revoke a key |

## Fleet (only when `FLEET_ENABLED=true`, requires persistent storage)

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

- `managed: false` means the instance belongs to no group and has no override - the
  dashboard pushes **no** policy and the instance keeps its local file (`changed:false`).
- A managed instance whose reported `config_hash` differs from desired receives the
  new `policy` + `filter_mode`; otherwise `changed:false`.
- `?wait=<duration>` (max 30s) enables long-polling; omitted/zero returns immediately.

## Static UI (catch-all)

`GET /` and any unmatched non-API path serve the embedded SPA (`index.html`),
behind UI auth. The login page and `/assets/*` remain public.
