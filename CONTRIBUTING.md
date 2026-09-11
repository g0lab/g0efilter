# Contributing

Thanks for helping improve g0efilter.

## Before you start

Discuss large features or filtering changes in an issue first. Small fixes,
documentation, and tests can go straight to a pull request.

The supported dev container provides Go, Node/pnpm, `golangci-lint`, and Docker.
For a local setup, follow the versions pinned by `go.work` and
`dashboard/ui/package.json`. Docker with the Compose plugin is required only for
end-to-end tests.

## AI usage

AI tools are welcome, but you must understand, review, and test their changes.

## Pull requests

Keep pull requests small and focused.

Use a conventional title when practical:

```text
fix(scope): short description
```

Explain what changed, why, and which checks you ran. Note any skipped or failed
checks.

## Validation

The agent, dashboard, shared library, controller, and test suites have separate
Go modules. The committed `go.work` joins them for local development, while the
canonical scripts test each module independently.

Run the script for each area you changed. The UI build is embedded by the
dashboard, so run `scripts/test-ui.sh` before the Go suite after a clean checkout
or a frontend change.

```sh
scripts/test-go.sh       # Go generation, tests, vet, lint, and manifest checks
scripts/test-action.sh   # GitHub Action scripts and tests
scripts/test-ui.sh       # UI type-check, lint, unit tests, and builds
```

`scripts/test-go.sh` runs the controller's envtest suite and installs its test
assets with the module's pinned `setup-envtest` tool. It requires
`golangci-lint`; workflow and chart linting also use `actionlint` and `ct` when
installed and report a skip otherwise. To run only the controller suite:

```sh
KUBEBUILDER_ASSETS="$(GOWORK=off go -C controller tool setup-envtest use -p path)" \
  GOWORK=off go -C controller test ./...
```

Parser, policy, and rendering changes should also get a fuzz run.
`scripts/test-go.sh` exercises each target's seed corpus; this mutates them:

```sh
FUZZTIME=1m scripts/test-fuzz.sh
```

A crash is written to `testdata/fuzz/<Target>/` next to the target. Turn it into a
named unit test or inline fuzz seed; generated corpus files are ignored. CI runs a
longer campaign nightly in `.github/workflows/fuzz.yaml`.

Run the relevant end-to-end modes for runtime, networking, security, or
cross-component changes. They need Docker:

```sh
cd tests/e2e
E2E_FILTER_MODE=https      go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns        go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns-strict go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
```

Images build automatically when missing; use `E2E_BUILD=force` after changing
agent or dashboard code. Controller, webhook, or Kubernetes packaging changes
should also run the opt-in Kubernetes phases. See `tests/e2e/README.md` for the
command, modes, and suite selection.

## Comments

Explain why, not what the code already says, and keep implementation comments
to two lines. Exported declarations, CRD field documentation, generated files
and tool directives are exempt: they are API documentation and are expected to
run longer. A block that opens `SECURITY:`, `CONCURRENCY:` or `COMPAT:` may run
longer too, where the constraint is what needs the room. Tutorials and
background belong in `docs/`.

`tests/repo/comments_test.go` only checks the comment blocks a change adds or
edits against the merge base, so unrelated work never has to fix the backlog.
A length check stops paragraphs; review still has to catch ten unnecessary
one-line comments.

## Generated files

After changing `dashboard/store/ent/schema/`, run
`scripts/gen-migration.sh <name>` and commit the generated client and migration.

After changing `controller/api/`, run `scripts/gen-controller.sh` and commit the
generated deepcopy methods, CRDs, controller RBAC, and Helm CRD templates.

After frontend changes, run `pnpm build` in `dashboard/ui/`. The generated
`dashboard/ui/dist/` contents are ignored and must not be committed.

## Security

Report vulnerabilities privately as described in
[Security](SECURITY.md#report-a-vulnerability).
