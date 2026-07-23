# GitHub Actions

The Action filters traffic from a GitHub-hosted Ubuntu runner and adds blocked
or audited connections to the job summary. Add it before the steps you want to
protect.

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

## Inputs

| Input | Description | Default |
| --- | --- | --- |
| `allowed-domains` | Newline-separated domains | empty |
| `allowed-ips` | Newline-separated IPs or CIDRs | empty |
| `egress-policy` | `block` or `audit` | `block` |
| `mode` | `https`, `dns`, or `dns-strict` | `https` |
| `log-level` | g0efilter log level | `INFO` |
| `image` | Container image | Action release image |
| `lockdown-runner` | Disable later sudo and Docker access | `false` |

The Action always permits GitHub's
[runner communication domains](https://docs.github.com/actions/reference/runners/self-hosted-runners)
and the runner's DNS resolvers. Add any package or container registries that the
job needs.

> [!NOTE]
> Only GitHub-hosted Ubuntu runners are supported. Later containers are filtered
> only when they use host networking. Jobs that use `container:` are not
> supported.

## Security limits

g0efilter blocks destinations outside the allowlist. It cannot stop data leaving
through allowed destinations, including GitHub services needed by the runner.
Logs, artifacts, caches, releases, and the GitHub API may still carry data.

Keep custom allow rules small and use restrictive job
[`permissions:`](https://docs.github.com/actions/tutorials/authenticate-with-github_token#modifying-the-permissions-for-the-github_token).
Network filtering does not limit what the job token can do.

## Lockdown mode

A later step can normally remove the filter through passwordless `sudo` or the
Docker socket. Set `lockdown-runner: true` to disable both after the filter
starts.

```yaml
- uses: g0lab/g0efilter@v0
  with:
    allowed-domains: api.github.com
    lockdown-runner: true
```

> [!WARNING]
> Use lockdown only on GitHub-hosted runners. Later steps cannot use `sudo`,
> Docker commands, or Docker-based actions. The final report may be empty
> because the post step cannot read container logs.
