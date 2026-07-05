# AGENTS.md

g0efilter is a Go egress-filtering sidecar plus a small GitHub Action wrapper.

## Layout

- `cmd/` and `internal/` contain the Go binaries and packages.
- `action/` and `action.yml` contain the GitHub Action scripts and metadata.
- `tests/e2e/`, `scripts/`, and `examples/build/` contain Docker-based end-to-end coverage.
- `internal/dashboard/ui/` is embedded dashboard UI code.

## Build, Test, Lint

```sh
go mod tidy
git diff --exit-code
go vet ./...
go test -race -covermode=atomic -coverprofile=coverage.txt ./...
golangci-lint run --timeout=10m ./...
for f in action/*.js; do node --check "$f"; done
node --test 'action/*.test.js'
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

## Notes

- The e2e suite needs Docker and recreates the `examples/build` stack.
- DNS filtering depends on kernel conntrack behaviour: keep DNS source-port and nftables changes covered by e2e.

## Style

- Keep comments short and only for non-obvious constraints, security rationale, or workarounds.
- Let code and test names carry the obvious parts.
- Use no em dashes and no emojis.
