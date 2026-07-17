# Remote unblock

Administrators can unblock domains/IPs from the dashboard UI; g0efilter instances poll for pending requests and update their policy files.

This is the compatibility transport. The fleet control-plane plan moves command
delivery onto bounded long-poll reconciliation while retaining explicit REST
acknowledgements; see [dashboard-control-plane.md](dashboard-control-plane.md).

> [!WARNING]
> Disabled by default. Only enable behind authentication middleware: `POST /api/v1/unblocks` must be protected (Authelia, Authentik, PocketID, ...) or anyone reaching the dashboard can modify your allowlist.

## Enabling

Set these on **g0efilter** (the dashboard exposes the API-key endpoints automatically, no flag needed):

| Variable | Required | Description |
|----------|----------|-------------|
| `ENABLE_REMOTE_UNBLOCK` | yes | Set to `true` to start the poller |
| `DASHBOARD_HOST` | yes | Dashboard URL (already set for log shipping) |
| `DASHBOARD_API_KEY` | yes | Must match `API_KEY` on the dashboard |
| `UNBLOCK_POLL_INTERVAL` | no | Poll interval, default `10s` |

g0efilter logs `remote_unblock.enabled` at startup once all three required values are set. Approved requests are appended to the instance's policy file and applied via live reload.

## API endpoints

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

## Traefik example

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
