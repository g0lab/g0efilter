## Summary

What changed and why? Link related issues.

## Validation

List the relevant checks you ran, and explain any
skipped or failed checks.

```sh
scripts/test-go.sh
scripts/test-action.sh
scripts/test-ui.sh
(cd tests/e2e && E2E_FILTER_MODE=https      go test -count=1 -p 1 -parallel=1 -timeout=35m ./...)
(cd tests/e2e && E2E_FILTER_MODE=dns        go test -count=1 -p 1 -parallel=1 -timeout=35m ./...)
(cd tests/e2e && E2E_FILTER_MODE=dns-strict go test -count=1 -p 1 -parallel=1 -timeout=35m ./...)
```

## Reviewer Notes

Call out risks, breaking changes, migrations, known failures, or follow-up work.
