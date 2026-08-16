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

`NOTIFICATION_URLS` goes in `.env` if you enable alerting: the URLs embed a token,
so keep them out of `docker-compose.yaml` and out of version control. On
Kubernetes use `notifications.urlsSecret`, and in GitHub Actions a repository
secret.

Stop the example:

```sh
docker compose down
```

See [configuration](../docs/configuration.md) and
[policy](../docs/policy.md) for more options.

Other examples:

- [Kubernetes with Kustomize](kubernetes/)
- [a Helm library-chart consumer](helm/demo/)
- [rootless Podman with Quadlet](podman/)
- [building the images from source with Docker or Podman Compose](build/)
