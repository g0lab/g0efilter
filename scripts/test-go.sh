#!/usr/bin/env bash
# Go test runner, used by CI and runnable locally:
#   scripts/test-go.sh
# Confirms every production module is tidy, vets, runs the race-enabled suites
# with coverage, and runs golangci-lint with the same arguments used by CI.
# Requires the Go toolchain and golangci-lint.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo ">>> ent client is up to date"
GOWORK=off go -C dashboard generate ./store/ent/...
GOWORK=off go -C dashboard mod tidy
git diff --exit-code -- dashboard/store/ent \
  ':(exclude)dashboard/store/ent/migrate/main.go' dashboard/go.mod dashboard/go.sum

echo ">>> migrations match the ent schema"
# No-op when in sync; a drift rewrites atlas.sum (tracked), tripping the diff.
GOWORK=off go -C dashboard run -mod=mod store/ent/migrate/main.go ci-check
GOWORK=off go -C dashboard mod tidy
git diff --exit-code -- dashboard/store/migrations dashboard/go.mod dashboard/go.sum

echo ">>> golangci-lint config verify"
golangci-lint config verify


for module in shared agent dashboard tests/repo; do
  echo ">>> $module module"
  GOWORK=off go -C "$module" mod tidy
  git diff --exit-code -- "$module/go.mod" "$module/go.sum"
  GOWORK=off go -C "$module" vet ./...
  GOWORK=off go -C "$module" test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.txt ./...
  (cd "$module" && GOWORK=off golangci-lint run --timeout=10m ./...)
done

echo ">>> controller module"
GOWORK=off go -C controller mod tidy
git diff --exit-code -- controller/go.mod controller/go.sum
GOWORK=off go -C controller vet ./...
# envtest runs a real kube-apiserver and etcd so the generated CRDs are exercised by
# the API server's own validation, not just by the Go types.
KUBEBUILDER_ASSETS="$(GOWORK=off go -C controller tool setup-envtest use -p path)" \
  GOWORK=off go -C controller test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.txt ./...
(cd controller && GOWORK=off golangci-lint run --timeout=10m ./...)
