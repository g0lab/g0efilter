[![docker pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter.svg?label=docker%20pulls)](https://hub.docker.com/r/g0lab/g0efilter)
[![g0efilter CI](https://github.com/g0lab/g0efilter/actions/workflows/ci.yaml/badge.svg)](https://github.com/g0lab/g0efilter/actions/workflows/ci.yaml)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fg0lab%2Fg0efilter.svg?type=shield&issueType=security)](https://app.fossa.com/projects/git%2Bgithub.com%2Fg0lab%2Fg0efilter?ref=badge_shield&issueType=security)
[![Go Report Card](https://goreportcard.com/badge/g0lab/g0efilter)](https://goreportcard.com/report/g0lab/g0efilter)
[![codecov](https://codecov.io/gh/g0lab/g0efilter/graph/badge.svg?token=owO27TfE79)](https://codecov.io/gh/g0lab/g0efilter)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/6221eed68e504016acd2ec9d951bc031)](https://app.codacy.com/gh/g0lab/g0efilter/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![License](https://img.shields.io/github/license/g0lab/g0efilter.svg)](https://github.com/g0lab/g0efilter/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/g0lab/g0efilter?label=latest%20release)](https://github.com/g0lab/g0efilter/releases)

> [!WARNING]
> g0efilter is in active development and its configuration may change often.

g0efilter is a lightweight container designed to filter outbound (egress) traffic from attached container workloads. Run g0efilter alongside your workloads and attach them to its network namespace to enforce a simple IP and domain allowlist policy.

### How it works

* Attach containers to g0efilter using `network_mode: "service:g0efilter"` in Docker Compose.
* A policy file defines the allowed IPs/CIDRs and domains.
* Using nftables, g0efilter (when in SNI filter mode) allows traffic to specified IPs/CIDRs or redirects outbound HTTP (port 80) and HTTPS (port 443) to local services.
* These local services check the HTTP Host header or TLS SNI extension in the ClientHello and allow or block connections according to the policy.  
* Filtering behaviour depends on the selected mode: sni (default) or dns.  
* The optional g0efilter-dashboard displays real-time traffic and enforcement actions.

> [!NOTE]
> Attached containers share g0efilter’s network namespace.  
> g0efilter listens on `HTTP_PORT` (default `8080`) and `HTTPS_PORT` (default `8443`) for inspection.  
> Avoid binding these ports in attached containers or change them via environment variables.

### SNI/Host Header filtering behaviour (default)

* All IPs listed in the policy file bypass any redirection.
* In SNI mode (default), traffic to ports 80 and 443 is redirected to local services that check the HTTP Host header or TLS SNI against the policy file, anything not matching is blocked by nftables.

### DNS filtering behaviour

* All IPs listed in the policy file bypass any redirection.
* In DNS mode, traffic to port 53 is redirected to an internal DNS server that only resolves domains that match the policy. Non-policy domains simply fail to resolve, but direct IP connections are allowed (no default deny), so this mode can potentially be bypassed.

### Dashboard container

The optional **g0efilter-dashboard** container runs a small web UI on **port 8081** (by default). If `DASHBOARD_HOST` and `DASHBOARD_API_KEY` are set, the **g0efilter** container will ship logs to the dashboard.

Example Dashboard Screenshot:

![g0efilter-dashboard-example](https://raw.githubusercontent.com/g0lab/g0efilter/main/examples/images/g0efilter-dashboard-example.png)


### Quick Start

Refer to the [examples](https://github.com/g0lab/g0efilter/tree/main/examples).

### Example policy.yaml

```yaml
allowlist:
  ips:
    - "1.1.1.1"
    - "192.168.0.0/16"
    - "10.1.1.1"
  domains:
    - "github.com"
    - "*.alpinelinux.org"
```

### Environment variables

### g0efilter

| Variable            | Description                                        | Default             |
| ------------------- | -------------------------------------------------- | ------------------- |
| `LOG_LEVEL`         | Log level (INFO, DEBUG, etc.)                      | `INFO`              |
| `LOG_FORMAT`        | Log output format (json, console)                  | `json`              |
| `HOSTNAME`          | To identify which endpoint is sending the logs     | unset               |
| `HTTP_PORT`         | Local HTTP port                                    | `8080`              |
| `HTTPS_PORT`        | Local HTTPS port                                   | `8443`              |
| `POLICY_PATH`       | Path to policy file inside container               | `/app/policy.yaml`  |
| `FILTER_MODE`       | `sni` (TLS SNI) or `dns` (DNS name filtering)      | `sni`               |
| `DNS_PORT`          | DNS listen port                                    | `53`                |
| `DNS_UPSTREAMS`     | Upstream DNS servers (comma-separated)             | `127.0.0.11:53`     |
| `DASHBOARD_HOST`    | Dashboard URL for log shipping                     | unset               |
| `DASHBOARD_API_KEY` | API key for dashboard authentication               | unset               |
| `LOG_FILE`          | Optional path for persistent log file              | unset               |
| `NFLOG_BUFSIZE`     | Netfilter log buffer size                          | `96`                |
| `NFLOG_QTHRESH`     | Netfilter log queue threshold                      | `50`                |
| `NOTIFICATION_HOST`            | Gotify server URL for security alert notifications | unset               |
| `NOTIFICATION_KEY`             | Gotify application key for authentication          | unset               |
| `NOTIFICATION_BACKOFF_SECONDS` | Rate limit backoff period for duplicate alerts    | `60`                |

### g0efilter-dashboard

| Variable       | Description                                                                                                       | Default |
| -------------- | ----------------------------------------------------------------------------------------------------------------- | ------- |
| `PORT`         | Address/port the dashboard listens on (HTTP UI + API). Can be just a port (`8081`) or address+port (`:8081`)     | `:8081` |
| `API_KEY`      | API key used to authenticate incoming log data from the `g0efilter` container. Must match `DASHBOARD_API_KEY`    | unset   |
| `LOG_LEVEL`    | Log level (`INFO`, `DEBUG`, etc.)                                                                                 | `INFO`  |
| `BUFFER_SIZE`  | In-memory buffer size for events. Controls how many events can be queued before dropping                          | `5000`  |
| `READ_LIMIT`   | Maximum number of events returned per read/API request                                                            | `500`   |
| `SSE_RETRY_MS` | Server-Sent Events (SSE) client retry interval in milliseconds                                                    | `2000`  |
| `RATE_RPS`     | Maximum average requests per second (rate-limit)                                                                  | `50`    |
| `RATE_BURST`   | Maximum burst size for rate-limiting (in requests)                                                                | `100`   |


### Example docker-compose.yaml

```yaml
services:
  g0efilter:
    image: docker.io/g0lab/g0efilter:latest
    container_name: g0efilter
    volumes:
      - ./policy.yaml:/app/policy.yaml:ro
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN # Required for nftables modification
    security_opt:
      - no-new-privileges
    # Host-exposed port for dashboard (dashboard runs in same netns)
    ports:
      - 8081:8081 # Dashboard port
    read_only: true
    env_file:
      - .env

  g0efilter-dashboard:
    image: docker.io/g0lab/g0efilter-dashboard:latest
    container_name: g0efilter-dashboard
    # optional - custom user
    # user: 1000:1000
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges
    read_only: true
    env_file:
      - .env.dashboard
    network_mode: "service:g0efilter"

  example-container:
    image: alpine:latest
    container_name: example-container
    command: >
      sh -c "apk add --no-cache curl && tail -f /dev/null"
    depends_on:
      - g0efilter
    network_mode: "service:g0efilter"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
