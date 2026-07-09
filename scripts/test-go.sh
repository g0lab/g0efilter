#!/usr/bin/env bash
# Go test runner, used by CI and runnable locally:
#   scripts/test-go.sh
# Confirms go.mod/go.sum are tidy, vets, and runs the race-enabled suite with
# coverage. Requires the Go toolchain. Lint is run separately (golangci-lint).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo ">>> go mod tidy check"
go mod tidy
git diff --exit-code -- go.mod go.sum

echo ">>> go vet"
go vet ./...

echo ">>> go test (race + coverage)"
go test -race -covermode=atomic -coverprofile=coverage.txt ./...
