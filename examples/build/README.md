# Build from source

From the repository root, build and start the agent and dashboard with Docker:

```sh
docker compose -f examples/build/compose.yaml up --build
```

For rootless Podman, install a Compose provider and run:

```sh
podman compose -f examples/build/compose.yaml up --build
```

Open <http://localhost:8081>. Use the same command with `down` to stop the
example.

The `build-only` profile also builds the controller image:

```sh
docker compose -f examples/build/compose.yaml --profile build-only build
```
