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
| `identity` | Names this runner in alerts and logs | `<owner>/<repo>/<workflow>` |
| `notification-urls` | Whitespace-separated shoutrrr URLs to alert on | empty |
| `notification-ignore` | Newline-separated rules for blocks that should not alert or clutter the report | `local` |

The Action always permits GitHub's
[runner communication domains](https://docs.github.com/actions/reference/runners/self-hosted-runners)
and the runner's DNS resolvers. Add any package or container registries that the
job needs.

> [!NOTE]
> Only GitHub-hosted Ubuntu runners are supported. Later containers are filtered
> when they use host networking, Docker's default bridge, or a `br-*`
> user-defined bridge. Traffic between containers is left to Docker's own
> isolation rules.
> Jobs that use `container:` are not supported because the Action is initialized
> inside that job container rather than on the runner host.

## Job report

The Action logs its allowlist in a collapsed `g0efilter allowlist` group. A `+`
marks workflow entries rather than the always-permitted baseline.

The post step then writes an egress report to the job summary:

- the mode, egress policy, and image that ran;
- a count of allowed, blocked, and audited decisions, by unique host;
- every blocked host with its component and destination, with the blocks matching
  `notification-ignore` collapsed into their own group;
- every audited host, which is reported but not blocked;
- every allowed host that was reached, collapsed;
- the full allowlist, split into workflow entries and the baseline.

The report is written even when nothing was blocked. The counts always cover every
decision, including the blocks folded away by `notification-ignore`.

## Security limits

Filtering cannot stop data leaving through allowed destinations, including
GitHub services, logs, artifacts, caches, releases, and the API.

Keep custom allow rules small and use restrictive job
[`permissions:`](https://docs.github.com/actions/tutorials/authenticate-with-github_token#modifying-the-permissions-for-the-github_token).
Network filtering does not limit what the job token can do.

g0efilter reads TLS SNI and HTTP Host metadata but does not decrypt TLS, inject
a certificate authority, wrap container runtimes, or inspect encrypted paths
and request bodies.

## Notifications

Alert on blocked egress while the job runs. `notification-urls` takes one or more
[shoutrrr](https://shoutrrr.nickfedor.com/) URLs, so any service it supports
works.

```yaml
- uses: g0lab/g0efilter@v0
  with:
    allowed-domains: api.github.com
    notification-urls: ${{ secrets.NOTIFICATION_URLS }}
```

Keep the URLs in repository or organization secrets: they carry tokens. Each URL
is masked in the log and passed to the container through the environment, not the
command line where any process on the runner could read it.

Alerts are titled with `identity`, which defaults to `<owner>/<repo>/<workflow>`.
Set it when several workflows notify the same channel.

`notification-ignore` defaults to `local`, dropping the multicast, link-local, and
private-range noise a runner always produces. It also decides what the job summary
folds away, so it quietens the report even with no `notification-urls` set. Add
`ip-only` to alert only on domain blocks:

```yaml
    notification-ignore: |
      local
      ip-only
```

See [configuration](configuration.md#notifications) for the full rule syntax.

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
