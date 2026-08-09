# Contributing

Thanks for helping improve g0efilter.

## Before you start

Discuss large features or filtering changes in an issue first. Small fixes,
documentation, and tests can go straight to a pull request.

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

Run the script for each area you changed:

```sh
scripts/test-go.sh
scripts/test-action.sh
scripts/test-ui.sh
```

Parser and policy changes should also get a fuzz run. `scripts/test-go.sh` already
exercises each target's seed corpus; this mutates:

```sh
FUZZTIME=1m scripts/test-fuzz.sh
```

A crash is written to `testdata/fuzz/<Target>/` next to the target. Turn it into a
named unit test or inline fuzz seed; generated corpus files are ignored. CI runs a
longer campaign nightly in `.github/workflows/fuzz.yaml`.

Run the end-to-end tests for filtering changes. They need Docker:

```sh
cd tests/e2e
E2E_FILTER_MODE=https      go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns        go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
E2E_FILTER_MODE=dns-strict go test -count=1 -v -p 1 -parallel=1 -timeout=35m ./...
```

Images build automatically when missing; use `E2E_BUILD=force` after changing
agent or dashboard code. See `tests/e2e/README.md` for modes and suite selection.

After changing `dashboard/store/ent/schema/`, run
`scripts/gen-migration.sh <name>` and commit the generated client and migration.

## Security

Report vulnerabilities privately as described in
[Security](SECURITY.md#report-a-vulnerability).
