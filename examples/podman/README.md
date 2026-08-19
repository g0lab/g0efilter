# Podman

g0efilter runs rootless under Podman 5 or later as uid 65534 with
`CAP_NET_ADMIN` inside the user namespace.

This example uses Quadlet for a systemd-managed service. For a short-lived
Podman Compose demo that builds the images, see [build from source](../build/).

The example uses DNS-strict mode with Cloudflare's `1.1.1.1` resolver so it does
not depend on host-specific Podman DNS addresses. Change `DNS_UPSTREAMS` in
`g0efilter.container` if you use another resolver.

These [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
files generate systemd units when systemd reloads. They do not use
`podman generate systemd`.

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

- The policy volume needs `:Z` on Fedora, RHEL and derivatives for SELinux.
  Without it the container cannot read the mount.
- Podman's default OCI image format can drop image health-check
  metadata. The Quadlet declares its own health check so the published image works.
  If you build the image yourself for other Podman workflows, add `--format docker`
  to preserve the Dockerfile health check:

  ```sh
  podman build --format docker -f examples/build/Containerfile -t g0efilter:local .
  ```

- `Notify=healthy` keeps `g0efilter.service` in its starting state
  until the image health check passes. `Requires=` and `After=` then keep the
  workload from starting before the filter is ready.

Policy, filtering, live reload, and subcommands behave as under Docker. See
[configuration](../../docs/configuration.md).
