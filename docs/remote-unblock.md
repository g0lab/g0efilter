# Remote unblock

Remote unblock lets dashboard users add a domain or IP to an instance's policy.
The instance polls for approved requests and applies them through live reload.

> [!WARNING]
> Remote unblock is disabled by default. Keep the dashboard UI authenticated.
> With `AUTH_MODE=none`, place it behind an authenticating reverse proxy.

## Enable it

Set these variables on g0efilter:

| Variable | Required | Description |
| --- | --- | --- |
| `ENABLE_REMOTE_UNBLOCK` | yes | Set to `true` |
| `DASHBOARD_HOST` | yes | Dashboard URL |
| `DASHBOARD_API_KEY` | yes | Active machine API key |
| `UNBLOCK_POLL_INTERVAL` | no | Poll interval; default `10s` |

At startup, `remote_unblock.enabled` confirms that the required settings were
found. Approved requests are appended to the local policy file.

## Reverse proxies

Machine routes use `X-Api-Key`; browser routes use the dashboard's UI
authentication. If a reverse proxy adds SSO, allow these machine routes through
without browser authentication:

- `POST /api/v1/logs`
- `GET /api/v1/unblocks`
- `POST /api/v1/unblocks/ack`
- `GET /health`

Protect all other routes with UI authentication. See
[dashboard endpoints](endpoints.md) for the full route list and auth realms.
