# Podman

g0efilter runs under Podman, including rootless, with no changes: the image runs as
uid 65534 and carries `CAP_NET_ADMIN` as a file capability, which applies inside a
rootless user namespace too.

These files are [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
units. systemd generates the services from them, so there is no `podman generate
systemd` step to re-run - that command is deprecated.

## Install

```sh
mkdir -p ~/.config/containers/systemd ~/g0efilter/policy
cp examples/podman/*.pod examples/podman/*.container ~/.config/containers/systemd/

cat > ~/g0efilter/policy/policy.yaml <<'EOF'
allowlist:
  domains:
    - 'example.com'
EOF

systemctl --user daemon-reload
systemctl --user start g0efilter example-app
```

For a system-wide install put the units in `/etc/containers/systemd/` and drop
`--user`.

## Verify

```sh
systemctl --user status g0efilter
journalctl --user -u g0efilter -n 20

podman exec systemd-example-app curl -fsS https://example.com
podman exec systemd-example-app curl -fsS --max-time 5 https://github.com
```

`journalctl` should show `startup.ready`, then an `ALLOWED` verdict for the first
request and a `BLOCKED` one for the second.

## Differences from Docker

- **SELinux.** The policy volume needs `:Z` on Fedora, RHEL and derivatives, as above.
  Without it the container cannot read the mount.
- **HEALTHCHECK.** Podman's default OCI image format drops it. It only matters if you
  build the image yourself; add `--format docker` to keep it:

  ```sh
  podman build --format docker -f examples/build/Containerfile -t g0efilter:local .
  ```

- **Ordering.** Compose has no dependency ordering for a shared network namespace, so
  the Docker example relies on the filter starting first. Quadlet makes it explicit
  with `Requires=`/`After=`, as in `example-app.container`.

Everything else - the policy format, filter modes, live reload and the `caps` and
`policy` subcommands - behaves identically. See [configuration](../../docs/configuration.md).
