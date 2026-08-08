#!/usr/bin/env bash
# Go test runner, used by CI and runnable locally:
#   scripts/test-go.sh
# Confirms go.mod/go.sum are tidy, vets, runs the race-enabled suite with
# coverage, and runs golangci-lint with the same arguments used by CI.
# Requires the Go toolchain and golangci-lint.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo ">>> go mod tidy check"
go mod tidy
git diff --exit-code -- go.mod go.sum

echo ">>> ent client is up to date"
go generate ./dashboard/store/ent/...
go mod tidy
git diff --exit-code -- dashboard/store/ent go.mod go.sum

echo ">>> migrations match the ent schema"
# No-op when in sync; a drift rewrites atlas.sum (tracked), tripping the diff.
go run -mod=mod dashboard/store/ent/migrate/main.go ci-check
go mod tidy
git diff --exit-code -- dashboard/store/migrations go.mod go.sum

echo ">>> go vet"
go vet ./...

echo ">>> go test (race + coverage)"
go test -race -covermode=atomic -coverprofile=coverage.txt ./...

echo ">>> golangci-lint config verify"
golangci-lint config verify

echo ">>> golangci-lint"
golangci-lint run --timeout=10m ./...

# The controller is a separate module so controller-runtime stays out of the agent's
# dependency tree; it needs its own vet, test and lint pass.
echo ">>> controller module"
cd "$ROOT/controller"
go mod tidy
git diff --exit-code -- go.mod go.sum
go vet ./...
# envtest runs a real kube-apiserver and etcd so the generated CRDs are exercised by
# the API server's own validation, not just by the Go types.
KUBEBUILDER_ASSETS="$(go tool setup-envtest use -p path)" go test -race ./...
golangci-lint run --timeout=10m ./...
