# GitHub Actions

g0efilter can filter egress from GitHub Actions runners. The action starts the g0efilter container with host networking, so all traffic from the job (and later steps) is inspected, and adds a report of blocked/audited connections to the job summary.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Filter egress
        uses: g0lab/g0efilter@v0
        with:
          egress-policy: block   # or 'audit' to log without blocking
          allowed-domains: |
            *.npmjs.org
            registry.npmjs.org

      - uses: actions/checkout@v7
      # ... the rest of the job runs behind the filter
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `allowed-domains` | Newline-separated domains (wildcards and regex supported) | |
| `allowed-ips` | Newline-separated IPs/CIDRs | |
| `egress-policy` | `block` or `audit` | `block` |
| `mode` | `https` (SNI/Host inspection), `dns` (resolution filtering), or `dns-strict` (resolution filtering plus kernel connection-time enforcement) | `https` |
| `log-level` | g0efilter log level | `INFO` |
| `image` | Container image to run | matches the action's release tag, or `:latest` for branch refs |

GitHub's [documented runner communication domains](https://docs.github.com/actions/reference/runners/self-hosted-runners) and the runner's DNS resolvers are always allowed so the workflow itself keeps working. Package registries are **not** in the baseline - if a step pulls containers or packages, add the registry (`ghcr.io`, `*.pkg.github.com`, `registry.npmjs.org`, ...) to `allowed-domains`.

> [!NOTE]
> Limitations: GitHub-hosted Ubuntu runners only. Traffic from Docker containers started by later steps is filtered only when they use `--network host`; jobs that run inside a container (`container:`) are not supported.
