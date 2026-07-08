# AGENTS.md

g0efilter is a Go egress-filtering sidecar plus a small GitHub Action wrapper.

## Layout

- `cmd/` and `internal/` contain the Go binaries and packages.
- `action/` and `action.yml` contain the GitHub Action scripts and metadata.
- `docs/` contains detailed user documentation split out from the README.
- `tests/e2e/`, `scripts/`, and `examples/build/` contain Docker-based end-to-end coverage.
- `internal/dashboard/ui/` is embedded dashboard UI code.

## Build, Test, Lint

Run the groups that match the files touched.

Go:

```sh
scripts/test-go.sh                    # go mod tidy check, vet, race + coverage
golangci-lint run --timeout=10m ./...
```

Action:

```sh
scripts/test-action.sh                # node --check, unit tests, setup.sh checks
```

Docker/e2e:

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

## Notes

- The e2e suite needs Docker and recreates the `examples/build` stack.
- DNS filtering depends on kernel conntrack behaviour: keep DNS source-port and nftables changes covered by e2e.
- Keep README front-door content and detailed `docs/` pages in sync when changing user-facing behavior, configuration, or GitHub Action inputs.

## Style

- Keep comments short and only for non-obvious constraints, security rationale, or workarounds.
- Let code and test names carry the obvious parts.
- Use no em dashes, no emojis, and no other unicode characters when not needed.
