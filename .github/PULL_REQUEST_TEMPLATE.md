## Summary

What changed and why? Link related issues.

## Validation

List the relevant checks you ran, and explain any
skipped or failed checks.

```sh
scripts/test-go.sh
scripts/test-action.sh
scripts/test-ui.sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

## Reviewer Notes

Call out risks, breaking changes, migrations, known failures, or follow-up work.
