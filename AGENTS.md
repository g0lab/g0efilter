# AGENTS.md

g0efilter is a Go egress-filtering sidecar plus a small GitHub Action wrapper.

## Layout

The repository is component-first: binaries and their packages live under
`agent/` and `dashboard/`, with `main.go` at each component root. Shared Go
packages live under `shared/`. The GitHub Action is under `action/` with its
metadata in `action.yml`.

Other top-level areas are self-describing: `docs/`, `examples/`, `scripts/`, and
`tests/e2e/`. Prefer inspecting the current tree over maintaining package lists
here.

The dashboard frontend is under `dashboard/ui/`. Its generated `dist/` is
embedded by Go but is not committed; build it with `pnpm build`. Shared UI types
in `dashboard/ui/src/lib/types.ts` mirror the Go dashboard model.

## Build, Test, Lint

Run the repository scripts that match the files changed; they are the canonical
source for the checks CI performs. Tool versions live in the relevant repository
configuration.

```sh
scripts/test-go.sh       # Go generation, migrations, tests, vet, and lint
scripts/test-action.sh   # GitHub Action
scripts/test-ui.sh       # dashboard UI
```

For a database schema change, edit `dashboard/store/ent/schema/`, then run
`scripts/gen-migration.sh <name>`. Commit both the generated Ent client and the
migration.

Use `scripts/dev.sh` for local dashboard development; add `--traffic` for live
synthetic traffic. The `.devcontainer/` contains the supported full toolchain.

Docker end-to-end tests require Docker and recreate the `examples/build` stack:

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

## Conventions

- Keep shared synthetic fixtures canonical in `dashboard/demo/scenarios.json`.
- Keep README front-door content and detailed `docs/` pages in sync when
  changing user-facing behavior, configuration, or Action inputs.
- Cover DNS source-port, conntrack, and nftables changes with end-to-end tests.

## Style

- Use clear code and test names for routine intent and behavior.
- Add comments only for non-obvious constraints, security rationale, or
  workarounds.
- Use plain ASCII unless a file, test fixture, or domain-specific term requires
  unicode.
