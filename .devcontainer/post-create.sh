#!/usr/bin/env bash
# Provisions the dev container with the full g0efilter toolchain:
# Go + golangci-lint + Ent codegen (backend) and pnpm (dashboard UI).
# Migrations are generated from the Ent schema by Atlas-as-a-library
# (scripts/gen-migration.sh) - no atlas binary required.
# Docker-in-docker (from the devcontainer feature) covers the e2e suite.
set -euo pipefail

echo ">>> Go tooling"
GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"
# ent CLI version tracks the dashboard module.
go install "entgo.io/ent/cmd/ent@$(GOWORK=off go -C dashboard list -m -f '{{.Version}}' entgo.io/ent)"

# golangci-lint latest release
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
  | sh -s -- -b "$GOBIN"

echo ">>> Go modules"
for module in shared agent dashboard controller tests tests/e2e; do
  GOWORK=off go -C "$module" mod download
done

echo ">>> pnpm (via corepack) + UI deps"
corepack enable
# pnpm version tracks the packageManager field in dashboard/ui/package.json
(cd dashboard/ui && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack install && pnpm install --frozen-lockfile)

cat <<'MSG'

g0efilter dev container ready.

  Dev (seeded API/UI): scripts/dev.sh            (add --traffic for live data)
  Go tests           : scripts/test-go.sh
  UI tests/lint      : scripts/test-ui.sh
  e2e (docker)       : cd tests/e2e && go test -count=1 -parallel=1 ./...
  Go lint            : cd <module> && golangci-lint run ./...
  DB migration       : edit ent/schema, then scripts/gen-migration.sh <name>
  UI type-check/lint : cd dashboard/ui && pnpm check && pnpm lint
  UI build (embed)   : cd dashboard/ui && pnpm build
MSG
