# AGENTS.md

g0efilter is a Go egress-filtering sidecar plus a small GitHub Action wrapper.

## Layout

- `cmd/` and `internal/` contain the Go binaries and packages.
- `action/` and `action.yml` contain the GitHub Action scripts and metadata.
- `docs/` contains detailed user documentation split out from the README.
- `tests/e2e/`, `scripts/`, and `examples/build/` contain Docker-based end-to-end coverage.
- `internal/dashboard/ui/` is the dashboard frontend (Vite + Svelte 5 + TypeScript, pnpm).
  Source is `ui/src/` (`.ts` + `.svelte` with `lang="ts"`); shared types in `src/lib/types.ts`
  mirror the Go `model` JSON. Only the committed build output `ui/dist/` is embedded
  (`go:embed all:ui/dist`); after changing `ui/src/`, run `pnpm build` there and commit the
  regenerated `dist/`. The Docker image rebuilds the UI itself, so a stale commit can't ship.
- `internal/dashboard/store/` is SQLite persistence via **Ent** (`modernc.org/sqlite`, CGO-free):
  schema structs in `ent/schema/`, generated client in `ent/` (regenerate with
  `go generate ./internal/dashboard/store/ent/...`). Migrations are Atlas-generated versioned SQL
  in `migrations/` - edit a schema then run `scripts/gen-migration.sh <name>` (pure Go, no atlas
  binary); `store.Migrate` applies them at boot. Auth modes live in `auth.go`/`jwt.go`; fleet
  control plane in `fleet*.go` + `store/fleet.go`; optional persistent logs in `store/logstore.go`.

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

Dashboard frontend (only when `internal/dashboard/ui/src` changes):

```sh
scripts/test-ui.sh    # install, svelte-check, eslint, build + dist no-diff (Node 24)
# or, individually, from internal/dashboard/ui:
pnpm check            # svelte-check (TypeScript); keep at 0 errors
pnpm lint             # eslint (typescript-eslint + eslint-plugin-svelte)
pnpm build            # regenerates dist/ (commit it)
```

DB schema change: edit `internal/dashboard/store/ent/schema/*.go`, then
`scripts/gen-migration.sh <name>` (regenerates the Ent client + writes an Atlas migration).

Local dashboard dev: `scripts/dev.sh` (add `--traffic`) brings the backend and Vite UI up
together - UI on :5000 proxying `/api` to :8081, dev login/API key. A `.devcontainer/` provides
the full toolchain (Go + Node 24/pnpm + Ent codegen + docker-in-docker) for reproducible testing.

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

- Use clear code and test names for routine intent and behavior.
- Add short comments only when they explain non-obvious constraints, security rationale, or workarounds.
- Use plain ASCII unless a file, test fixture, or domain-specific term requires unicode.
