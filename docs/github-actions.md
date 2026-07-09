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
| `lockdown-runner` | Disable later sudo/Docker access and skip teardown (GitHub-hosted only) | `false` |

GitHub's [documented runner communication domains](https://docs.github.com/actions/reference/runners/self-hosted-runners) and the runner's DNS resolvers are always allowed so the workflow itself keeps working. Package registries are **not** in the baseline - if a step pulls containers or packages, add the registry (`ghcr.io`, `*.pkg.github.com`, `registry.npmjs.org`, ...) to `allowed-domains`.

> [!NOTE]
> Limitations: GitHub-hosted Ubuntu runners only. Docker containers started by later steps are filtered only when they use `--network host`; containers on the default bridge network are **not** filtered and can egress freely. Jobs that run inside a container (`container:`) are not supported.

## Threat model

g0efilter blocks arbitrary egress to destinations that are not allowlisted. It does not, and cannot, stop data leaving through destinations that *are* allowlisted, including the GitHub infrastructure that must stay reachable for the workflow to run.

**Blocked**

- Arbitrary internet egress to any domain or IP not in the allowlist (or, in `audit` mode, logged instead of blocked).

**Not blocked**

- Exfiltration through the always-allowed GitHub control plane. The baseline allowlist keeps `github.com`, `api.github.com`, `*.actions.githubusercontent.com`, and the Azure blob storage endpoints (`*.blob.core.windows.net`) reachable so the runner, logs, artifacts, and caches work. A compromised step can still stage data out through these paths, for example:
  - the GitHub API (`api.github.com`), bounded by the job token's permissions
  - workflow logs and job summaries
  - build artifacts and caches (uploaded to Azure blob storage)
  - releases, if the token can write them
- Anything you add to `allowed-domains` / `allowed-ips`. Keep the allowlist as small as the job needs.

g0efilter controls network egress; it does not constrain what the GitHub token itself can do. To narrow the control-plane side channel, set restrictive [`permissions:`](https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs) on the job and avoid write scopes it does not need.

## Lockdown mode

Passwordless `sudo` and Docker socket access are root-equivalent on GitHub-hosted runners, so by default a later (potentially compromised) step could remove the filter with `sudo nft flush ruleset` or `docker rm -f g0efilter`. Set `lockdown-runner: true` to close that gap: once the filter is confirmed active, the action restricts `/var/run/docker.sock` to root and disables `sudo` for the rest of the job. g0efilter keeps running (the Docker daemon is not stopped), and teardown is skipped because the runner VM is discarded after the job anyway.

```yaml
- uses: g0lab/g0efilter@v0
  with:
    allowed-domains: |
      api.github.com
    lockdown-runner: true
```

> [!WARNING]
> Lockdown caveats:
> - **GitHub-hosted runners only.** On self-hosted runners the skipped teardown leaves nftables rules in the host network namespace, which can break DNS/egress for later jobs.
> - Later steps or actions that need `sudo` or Docker will fail (including Docker-based `uses:` actions).
> - The final egress report may be empty, because the post step can no longer read the container logs once the Docker socket is locked down.
