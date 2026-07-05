## What Does This PR Do?

## Screenshots

## Contributing Guidelines

Have you read the [Contributing Guidelines](https://github.com/g0lab/g0efilter/blob/main/CONTRIBUTING.md)?

- [ ] I have read the contributing guidelines.
- [ ] For larger new features or behavior changes, I opened or commented on an issue, or this PR explains why that was not needed.

## Checks

Run the checks that match the files touched:

- [ ] Go changes: `go mod tidy`, `git diff --exit-code`, `go vet ./...`, `go test -race -covermode=atomic -coverprofile=coverage.txt ./...`, `golangci-lint run --timeout=10m ./...`
- [ ] Action changes: `for f in action/*.js; do node --check "$f"; done` and `node --test 'action/*.test.js'`
- [ ] Filter, script, e2e, or `examples/build` changes: `FILTER_MODE=https scripts/e2e.sh` and `FILTER_MODE=dns scripts/e2e.sh`

Normal PR e2e includes `12_load.sh`; the `load-test` workflow is for manual or labeled custom load runs.
