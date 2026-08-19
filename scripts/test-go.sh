#!/usr/bin/env bash
# Go test runner, used by CI and runnable locally:
#   scripts/test-go.sh
# Confirms every module is tidy, vets, runs the race-enabled suites with coverage,
# checks the generated controller output, and lints as CI does. Keep this a superset
# of the per-module steps in .github/workflows/ci-go.yaml.
# Requires the Go toolchain and golangci-lint; chart linting also needs ct.
set -euo pipefail
export GOEXPERIMENT=jsonv2
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


for module in shared agent dashboard tests; do
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

# The suite itself needs Docker and ~35m, so it runs separately (tests/e2e/README.md).
echo ">>> e2e module (vet and lint only)"
GOWORK=off go -C tests/e2e mod tidy
git diff --exit-code -- tests/e2e/go.mod tests/e2e/go.sum
GOWORK=off go -C tests/e2e vet ./...
(cd tests/e2e && GOWORK=off golangci-lint run --timeout=10m ./...)

echo ">>> generated controller output is up to date"
scripts/gen-controller.sh > /dev/null
git diff --exit-code -- deploy/crds controller/api deploy/controller \
  deploy/helm/g0efilter-controller/templates

# A bad ${{ }} expression stops GitHub loading the workflow at all, so its checks never
# report and a required one blocks every pull request.
echo ">>> workflow lint"
if command -v actionlint > /dev/null 2>&1; then
  actionlint
else
  echo "SKIPPED: actionlint is not installed (go install github.com/rhysd/actionlint/cmd/actionlint@latest)"
fi

echo ">>> chart lint"
if command -v ct > /dev/null 2>&1; then
  if ct list-changed --config .github/chart-testing.yaml | grep -q .; then
    ct lint --config .github/chart-testing.yaml
  else
    echo "no chart changes"
  fi
else
  echo "SKIPPED: ct is not installed, so a missing Chart.yaml version bump will only fail in CI"
fi
