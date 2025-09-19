[![g0efilter pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter.svg?label=g0efilter%20pulls)](https://hub.docker.com/r/g0lab/g0efilter)
[![g0efilter-dashboard pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter-dashboard.svg?label=g0efilter-dashboard%20pulls)](https://hub.docker.com/r/g0lab/g0efilter-dashboard)
[![Release](https://img.shields.io/github/v/release/g0lab/g0efilter?label=latest%20release)](https://github.com/g0lab/g0efilter/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/g0lab/g0efilter)](https://goreportcard.com/report/github.com/g0lab/g0efilter)
[![codecov](https://codecov.io/gh/g0lab/g0efilter/graph/badge.svg?token=owO27TfE79)](https://codecov.io/gh/g0lab/g0efilter)
[![License](https://img.shields.io/github/license/g0lab/g0efilter.svg)](https://github.com/g0lab/g0efilter/blob/main/LICENSE)

g0efilter is a lightweight container designed to filter outbound (egress) traffic from other containers.
You run g0efilter alongside your workloads, attach them to its network namespace, and it enforces a simple IP/domain allowlist policy. Using nftables, g0efilter permits traffic to the listed IPs or redirects traffic on ports 80 and 443 to local services. It then inspects the host headers (HTTP) or SNI headers in TLS hello packets (HTTPS) and allows or blocks traffic based on the defined policy.

* Attach containers to the g0efilter container using network_mode: "container:g0efilter" in Docker Compose.
* All outbound connections from attached containers are intercepted by g0efilter.
* A policy file defines which IPs, CIDRs, and domains are allowed; all other traffic is blocked.
* An optional g0efilter-dashboard displays real-time traffic and enforcement actions.
* Filtering behaviour depends on the selected mode: sni or dns.

### SNI/Host Header filtering behaviour (default)

* All IPs listed in the policy file bypass any redirection.
* In SNI mode (default), traffic to ports 443 and 80 is redirected to local services which inspect the SNI/Host headers and forward or block based on the domains listed in the policy file. Traffic not matching any rule is explicitly blocked at the nftables layer (default action: block).

### DNS filtering behaviour

* All IPs listed in the policy file bypass any redirection.
* In DNS mode, traffic to port 53 is redirected to a lightweight internal DNS service. This service only resolves domains that match those specified in the policy file. Domains not part of the policy simply fail to resolve (no explicit nftables drop). This method can be bypassed if IPs are directly connected to.

### Dashboard component

The optional `g0efilter-dashboard` container runs a small web UI on **port 8081** (by default). If `DASHBOARD_HOST` and `DASHBOARD_API_KEY` are set, the `g0efilter` will ship logs to the dashboard.

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
    security_opt:
      - no-new-privileges
    # Ports opened here for attached containers
    ports:
      - 8081:8081 # Dashboard port
    read_only: true
    env_file:
      - .env.example
    cap_add:
      - NET_ADMIN # Required for nftables modification

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
      - .env.dashboard.example
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
