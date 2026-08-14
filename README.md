[![agent pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter.svg?label=agent%20pulls)](https://hub.docker.com/r/g0lab/g0efilter)
[![dashboard pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter-dashboard.svg?label=dashboard%20pulls)](https://hub.docker.com/r/g0lab/g0efilter-dashboard)
[![controller pulls](https://img.shields.io/docker/pulls/g0lab/g0efilter-controller.svg?label=controller%20pulls)](https://hub.docker.com/r/g0lab/g0efilter-controller)
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
- Use the optional dashboard, remote unblock, and alerts to Gotify, ntfy,
  Telegram, Slack and every other shoutrrr supported service.
- Manage Kubernetes policies and inject sidecars with the optional controller.

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
    image: docker.io/g0lab/g0efilter:v0
    volumes:
      - ./policy/:/app/policy/
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges
    read_only: true

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
[the privilege model](docs/configuration.md#privileges) for how the container
runs unprivileged with only `NET_ADMIN`.

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

## Kubernetes

g0efilter runs as a native sidecar, so it filters the whole pod and the
application container needs no extra privileges. A Kustomize component can add it
without changing the workload source manifests.

```yaml
components:
  - github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.0
```

That covers Deployment, StatefulSet, DaemonSet, ReplicaSet, Job and CronJob.
There is also a Helm library chart for charts you maintain, a Helm post-renderer
for third-party charts you cannot edit, and a mutating webhook that injects the
sidecar at admission for pods you do not template at all.

To run it cluster-wide, install the control plane and label the namespaces to
filter:

```sh
helm install g0efilter oci://ghcr.io/g0lab/helm/g0efilter-controller \
  --namespace g0efilter-system --create-namespace
kubectl label namespace <namespace> g0efilter.g0lab.com/inject=enabled
```

Pods also need to match an `EgressPolicy`; the namespace label alone does not
trigger injection. See the [policy example](docs/kubernetes.md#writing-a-policy),
and start with `enforcement: audit` to see what it would deny.

Certificate Secret access is namespace-scoped and omitted when cert-manager owns
the certificate. The controller chart can also restrict webhook ingress to explicit
API-server CIDRs; see [webhook network isolation](docs/kubernetes.md#webhook-network-isolation).

Three charts are published, both as a conventional Helm repository at
`https://g0lab.github.io/g0efilter` and as OCI artifacts under
`oci://ghcr.io/g0lab/helm`:

| Chart | Type | Use |
| --- | --- | --- |
| `g0efilter-controller` | application | the control plane: controller, webhook and CRDs |
| `g0efilter-dashboard` | application | the dashboard the sidecars ship logs to |
| `g0efilter` | library | sidecar templates for a chart you maintain |

Render-time integrations mount a policy ConfigMap directly. The webhook uses a
controller to render one from each `EgressPolicy`. Kubernetes Events and
Prometheus metrics are optional.

See [Kubernetes](docs/kubernetes.md) for all four integrations, the full
`EgressPolicy` sidecar options, policy distribution, and the required namespace
label.

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

The loaded allowlist is logged in the workflow, and the job summary reports every
blocked, audited, and allowed host.

See [GitHub Actions](docs/github-actions.md) for inputs, built-in allow rules,
the job report, and security limits.

## Dashboard

[View the live demo](https://g0efilter-demo.g0lab.workers.dev/)

The optional dashboard shows live and saved traffic. Point g0efilter at it with
`DASHBOARD_HOST` and `DASHBOARD_API_KEY`. The dashboard can also manage API keys,
fleet policy, and remote unblock requests.

Its Helm chart supports externally managed credentials; declare the keys present
under `secrets.existingSecretKeys` so validation and recovery notes stay accurate.

See the [examples](examples/) for a complete setup. See
[dashboard authentication](docs/configuration.md#dashboard-authentication),
[persistent logs](docs/configuration.md#persistent-logs), and
[remote unblock](docs/remote-unblock.md) for its security requirements.

## Documentation

- [Filter modes](docs/modes.md)
- [Policy](docs/policy.md)
- [Kubernetes](docs/kubernetes.md)
- [Configuration and environment variables](docs/configuration.md)
- [Dashboard API endpoints](docs/endpoints.md)
- [GitHub Actions](docs/github-actions.md)
- [Remote unblock](docs/remote-unblock.md)

## Verify container signatures

Images use [Cosign](https://github.com/sigstore/cosign) keyless signatures.
Signatures are stored in `g0lab/signatures`:

```sh
COSIGN_REPOSITORY=docker.io/g0lab/signatures \
cosign verify g0lab/g0efilter:v0 \
  --certificate-identity-regexp=https://github.com/g0lab/g0efilter \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  -o text
```

Use `g0lab/g0efilter-dashboard:v0` to verify the dashboard image.

## License

MIT, see [LICENSE](LICENSE).
