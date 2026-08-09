# AGENTS.md

g0efilter is a Go egress-filtering sidecar with a dashboard, Kubernetes packaging, controller, and GitHub Action.

## Repository

* `agent/`, `dashboard/`, and `shared/` are separate Go modules joined by the committed root `go.work`.
* `controller/` is a separate Go module to keep `controller-runtime` out of the other production dependency trees.
* `dashboard/ui/` contains the frontend. Its generated `dist/` is embedded by Go but is not committed.
* `deploy/` contains the Kustomize, Helm, and Helm post-renderer implementations. They must inject the same sidecar configuration.
* `tests/` is a Go module for manifest and repository-wide tests; nested `tests/e2e/` remains isolated.

Prefer inspecting the repository tree over maintaining detailed package lists here.

## Build and Test

Run the canonical script for the files you changed:

```sh
scripts/test-go.sh       # Go generation, migrations, tests, vet, lint
scripts/test-action.sh   # GitHub Action
scripts/test-ui.sh       # dashboard UI
scripts/test-fuzz.sh     # every Go fuzz target, FUZZTIME per target
```

`VERSION` pins the release referenced by every manifest, doc and the injected
sidecar image. It holds plain SemVer; tags carry a `v`. Change it only with
`scripts/set-version.sh [X.Y.Z]`, which defaults to the next patch and also bumps
the Helm chart version.

Use `scripts/dev.sh` for local dashboard development; add `--traffic` for synthetic traffic. The `.devcontainer/` contains the supported full toolchain.

## Generated Files

For database schema changes:

1. Edit `dashboard/store/ent/schema/`.
2. Run `scripts/gen-migration.sh <name>`.
3. Commit the generated Ent client and migration.

After changing `controller/api/`, run:

```sh
scripts/gen-controller.sh
```

Commit both `controller/api/.../zz_generated.deepcopy.go` and the regenerated CRDs in `deploy/crds/`.

After frontend changes, run `pnpm build` in `dashboard/ui/`. Do not commit `dist/`.

## End-to-End Tests

Run E2E tests from `tests/e2e/`:

```sh
E2E_FILTER_MODE=https go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
```

Also test `dns` or `dns-strict` when relevant.

Always use `-count=1`; these tests use external container state and must not be cached.

After changing agent or dashboard code, rebuild test images with:

```sh
E2E_BUILD=force
```

Use `-run` to select a suite when appropriate. See `tests/e2e/README.md` for details.

## Project Rules

* Always update README, `docs/`, and `examples/` when changing user-facing behavior, configuration, or Action inputs.
* Always add E2E coverage for significant changes to runtime, networking, security, or cross-component behavior.
* Always keep sidecar configuration identical in `deploy/kustomize`, `deploy/helm` and the controller's injecting webhook; `tests/manifests/` and `controller/internal/webhook/parity_test.go` check this.
* Never add comments for obvious behavior; comment only on non-obvious constraints, security decisions, or workarounds.
* Never use Unicode unless required by the file, fixture, or domain; use ASCII.
