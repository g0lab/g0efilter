# Build from source

From the repository root, build and start the agent and dashboard:

```sh
docker compose -f examples/build/docker-compose-build.yaml up --build
```

Open <http://localhost:8081>. Stop the example with:

```sh
docker compose -f examples/build/docker-compose-build.yaml down
```

The optional `build-only` profile also builds the controller image:

```sh
docker compose -f examples/build/docker-compose-build.yaml --profile build-only build
```
