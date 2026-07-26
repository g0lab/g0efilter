# Contributing

Thanks for helping improve g0efilter.

## Before You Start

Discuss large features or filtering changes in an issue first. Small fixes,
documentation, and tests can go straight to a pull request.

## AI Usage

AI tools are welcome, but you must understand, review, and test their changes.

## Pull Requests

Keep pull requests small and focused.

Use a conventional title when practical:

```text
fix(scope): short description
```

Explain what changed, why, and which checks you ran. Note any skipped or failed
checks.

## Validation

Run the script for each area you changed:

```sh
scripts/test-go.sh
scripts/test-action.sh
scripts/test-ui.sh
```

Run the end-to-end tests for filtering changes. They need Docker:

```sh
cd tests/e2e
E2E_FILTER_MODE=https      go test -count=1 -v -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns        go test -count=1 -v -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns-strict go test -count=1 -v -parallel=1 -timeout=35m ./...
```

Images build automatically when missing; use `E2E_BUILD=force` after changing
agent or dashboard code. See `tests/e2e/README.md` for modes and suite selection.

After changing `dashboard/store/ent/schema/`, run
`scripts/gen-migration.sh <name>` and commit the generated client and migration.

## Security

Report vulnerabilities privately as described in
[Security](SECURITY.md#report-a-vulnerability).
