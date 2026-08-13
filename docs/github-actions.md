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

This repository filters its own workflows; see
[`description.yaml`](https://github.com/g0lab/g0efilter/blob/main/.github/workflows/description.yaml)
for a working example.

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
> when they use host networking, Docker's default bridge, or a `br-*`
> user-defined bridge; traffic between containers on one bridge is left alone.
> Jobs that use `container:` are not supported because the Action is initialized
> inside that job container rather than on the runner host.

## Job report

The Action logs its allowlist in a collapsed `g0efilter allowlist` group. A `+`
marks workflow entries rather than the always-permitted baseline.

The post step then writes an egress report to the job summary:

- the mode, egress policy, and image that ran;
- a count of allowed, blocked, and audited decisions, by unique host;
- every blocked host with its component and destination;
- every audited host, which is reported but not blocked;
- every allowed host that was reached, collapsed;
- the full allowlist, split into workflow entries and the baseline.

The report is written even when nothing was blocked.

## Security limits

Filtering cannot stop data leaving through allowed destinations, including
GitHub services, logs, artifacts, caches, releases, and the API.

Keep custom allow rules small and use restrictive job
[`permissions:`](https://docs.github.com/actions/tutorials/authenticate-with-github_token#modifying-the-permissions-for-the-github_token).
Network filtering does not limit what the job token can do.

g0efilter reads TLS SNI and HTTP Host metadata but does not decrypt TLS, inject
a certificate authority, wrap container runtimes, or inspect encrypted paths
and request bodies.

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
