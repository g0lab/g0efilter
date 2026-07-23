# g0efilter

[![agent pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter.svg?label=agent%20pulls)](https://hub.docker.com/r/g0lab/g0efilter)
[![dashboard pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter-dashboard.svg?label=dashboard%20pulls)](https://hub.docker.com/r/g0lab/g0efilter-dashboard)
[![CI (Go)](https://github.com/g0lab/g0efilter/actions/workflows/ci-go.yaml/badge.svg)](https://github.com/g0lab/g0efilter/actions/workflows/ci-go.yaml)
[![CI (UI)](https://github.com/g0lab/g0efilter/actions/workflows/ci-ui.yaml/badge.svg)](https://github.com/g0lab/g0efilter/actions/workflows/ci-ui.yaml)
[![Tests](https://github.com/g0lab/g0efilter/actions/workflows/test.yaml/badge.svg)](https://github.com/g0lab/g0efilter/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/g0lab/g0efilter/graph/badge.svg?token=owO27TfE79)](https://codecov.io/gh/g0lab/g0efilter)

> [!NOTE]
> Portions of this project were developed with the assistance of AI tools.

> [!WARNING]
> g0efilter is in active development and its configuration may change often.

g0efilter controls network traffic leaving your containers. It runs beside a
workload and applies IP and domain rules without decrypting TLS traffic.

## Features

- Allow or block traffic by IP, CIDR, or domain.
- Match exact domains, wildcards, or regular expressions.
- Choose HTTPS inspection, DNS filtering, or strict DNS filtering.
- Start with either a default-deny allowlist or a default-allow denylist.
- Test and build policies with audit and learning modes.
- Reload policies without restarting the container.
- Use the optional dashboard, remote unblock, process details, and Gotify alerts.

## Quick start

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

Save this as `docker-compose.yaml`:

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
      - SETUID
      - SETGID
      - CHOWN
    security_opt:
      - no-new-privileges

  example-container:
    image: docker.io/alpine/curl:latest
    command: sh -c "sleep infinity"
    network_mode: "service:g0efilter"
```

Start the services:

```sh
docker compose up -d
```

See the [examples](examples/) for complete Compose files and policies. See
[runtime user configuration](docs/configuration.md#running-as-a-non-root-user)
to change the container identity.

## Filter modes

Attached containers share g0efilter's network connection. Allowed IPs and CIDRs
pass through directly. Other traffic is handled by `FILTER_MODE`.

| Mode | Checks domains at | Blocks hardcoded IPs? | Best for |
| --- | --- | ---: | --- |
| `https` | Connection time, using TLS SNI or the HTTP Host header | Yes | Precise control of web traffic |
| `dns` | DNS lookup time | No | Simple, broad filtering |
| `dns-strict` | DNS lookup and connection time | Yes | Strict domain filtering on any port |

See [filter modes](docs/modes.md) for details and limits.

Use `dns-strict` when a workload connects to allowed domains over protocols or
ports other than HTTP and HTTPS. It allows IPs learned through approved DNS
lookups while blocking direct-IP and alternate-DNS bypasses.

> [!NOTE]
> Attached containers must not use g0efilter's internal HTTP, HTTPS, or DNS
> ports. The defaults are 65080, 65443, and 65053.

## Policy

```yaml
allowlist:
  ips:
    - '1.1.1.1'
    - '192.168.0.0/16'
  domains:
    - 'github.com'
    - '*.alpinelinux.org'
    - '/cache-[0-9]+\.example\.com/'
```

Mount the policy directory, not only the file. This keeps live reload working
when an editor replaces the file during save.

Policies can also use a default-allow denylist, learning mode, or audit mode.
See [policy](docs/policy.md) for patterns and policy modes. See
[environment variables](docs/configuration.md#environment-variables) for
configuration.

## GitHub Actions

The GitHub Action filters traffic from the runner. Add it before the steps you
want to protect.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Filter egress
        uses: g0lab/g0efilter@v0
        with:
          egress-policy: block
          allowed-domains: |
            *.npmjs.org
            registry.npmjs.org

      - uses: actions/checkout@v7
```

See [GitHub Actions](docs/github-actions.md) for inputs, built-in allow rules,
and security limits.

## Dashboard

[View the live demo](https://g0efilter-demo.g0lab.workers.dev/)

The optional dashboard shows live and saved traffic. Point g0efilter at it with
`DASHBOARD_HOST` and `DASHBOARD_API_KEY`. The dashboard can also manage API keys,
fleet policy, and remote unblock requests.

See the [examples](examples/) for a complete setup. See
[dashboard authentication](docs/configuration.md#dashboard-authentication),
[persistent logs](docs/configuration.md#persistent-logs), and
[remote unblock](docs/remote-unblock.md) for its security requirements.

## Documentation

- [Filter modes](docs/modes.md)
- [Policy](docs/policy.md)
- [Configuration and environment variables](docs/configuration.md)
- [Dashboard API endpoints](docs/endpoints.md)
- [GitHub Actions](docs/github-actions.md)
- [Remote unblock](docs/remote-unblock.md)

## Verify container signatures

Images use [Cosign](https://github.com/sigstore/cosign) keyless signatures.
Signatures are stored in `g0lab/signatures`:

```sh
COSIGN_REPOSITORY=docker.io/g0lab/signatures \
cosign verify g0lab/g0efilter:latest \
  --certificate-identity-regexp=https://github.com/g0lab/g0efilter \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  -o text
```

Use `g0lab/g0efilter-dashboard:latest` to verify the dashboard image.

## License

MIT, see [LICENSE](LICENSE).
