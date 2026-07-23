# Docker Compose example

This example starts g0efilter, its dashboard, and a test container.

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

Edit `policy/policy.yaml` to change the rules. Changes reload automatically.

Before using this setup outside your machine, replace
`your-secure-api-key-here` with the same random value in `.env` and
`.env.dashboard`.

Stop the example:

```sh
docker compose down
```

See [configuration](../docs/configuration.md) and
[policy](../docs/policy.md) for more options.
