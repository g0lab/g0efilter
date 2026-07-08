## Summary

Describe what changed and why. Link related issues if applicable.

## Validation

List the checks you ran. If a relevant check failed, was skipped, or was not applicable, explain why.

Suggested checks by area:

### Go

```sh
scripts/test-go.sh
golangci-lint run --timeout=10m ./...
```

### Action

```sh
scripts/test-action.sh
```

### Docker/e2e

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

## Reviewer Notes

Mention anything reviewers should pay extra attention to, including skipped checks, known failures, risks, breaking changes, migrations, or follow-up work.
