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

## Releasing

`VERSION` is the source of truth for the g0efilter release. Release tags must
match it and are what trigger publication. The preferred path is to run the
**Prepare Release** workflow. Leave its version input blank to use the next patch
version from `VERSION`, or enter a newer `X.Y.Z` version. The workflow validates
the input, runs `set-version.sh`, checks every pinned version, and opens a release
preparation PR.

For a manual next-patch bump, run `scripts/set-version.sh` with no arguments. To
select another newer version, pass it explicitly:

```sh
scripts/set-version.sh 0.9.0
git commit -am 'chore: release v0.9.0'
git tag v0.9.0
```

`VERSION` holds plain SemVer (`0.9.0`). Image tags, Kustomize `?ref=` and the tag
itself carry a `v`; the Helm `appVersion` and chart version do not.
`tests/repo/version_test.go` fails when a pin drifts, and the release workflow
fails when `VERSION` does not match the tag.

All chart `version` and `appVersion` fields track `VERSION`; `set-version.sh`
updates them together. Charts publish only from tags, and chart-testing rejects
template changes without a version bump. One `v<version>` GitHub release contains
the agent, dashboard, controller, and all three Helm chart packages. The same tag
also publishes their container images and OCI charts.

After changing `dashboard/store/ent/schema/`, run
`scripts/gen-migration.sh <name>` and commit the generated client and migration.

## Security

Report vulnerabilities privately as described in
[Security](SECURITY.md#report-a-vulnerability).
