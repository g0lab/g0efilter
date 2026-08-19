# Examples

The default example starts g0efilter, its dashboard, and a test container with
Docker Compose:

```sh
cd examples
docker compose up -d
```

Open <http://localhost:8081>. The dashboard prints its first admin password
once:

```sh
docker compose logs g0efilter-dashboard
```

Try an allowed domain from the test container:

```sh
docker compose exec example-container curl -I https://github.com
```

An unlisted domain is blocked:

```sh
docker compose exec example-container curl -I --max-time 5 https://example.com
```

Edit `policy/policy.yaml` to change the rules. Changes reload automatically.

Before using this setup outside your machine, replace
`your-secure-api-key-here` with the same random value in `.env` and
`.env.dashboard`.

If you enable alerts, put `NOTIFICATION_URLS` in `.env`. The URLs contain tokens,
so keep them out of `docker-compose.yaml` and version control. Kubernetes
integrations use a Secret reference. GitHub Actions should use a repository or
organization secret.

Stop the example:

```sh
docker compose down
```

See [configuration](../docs/configuration.md) and
[policy](../docs/policy.md) for more options.

Other examples:

- [Kubernetes with Kustomize](kubernetes/)
- [Helm library-chart consumer](helm/demo/)
- [Rootless Podman with Quadlet](podman/)
- [Build from source with Docker or Podman Compose](build/)
