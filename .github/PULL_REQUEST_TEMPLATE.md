## Summary

What changed and why? Link related issues.

## Validation

List the checks relevant to this change. Explain anything skipped or failing.

```sh
scripts/test-go.sh
scripts/test-action.sh
scripts/test-ui.sh
FUZZTIME=1m scripts/test-fuzz.sh
```

For runtime or integration changes, list the E2E modes and suites run. See the
[E2E guide](/g0lab/g0efilter/blob/main/tests/e2e/README.md) for the standard and
Kubernetes commands.

## Checklist

- [ ] Tests cover behavior changes, including E2E where required.
- [ ] User-facing docs and examples are updated where required.
- [ ] Generated files and deployment variants are updated where required.

## Reviewer Notes

Call out risks, breaking changes, migrations, known failures, or follow-up work.
