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
go install entgo.io/ent/cmd/ent@latest

# golangci-lint (pinned to the major the repo lints with)
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
  | sh -s -- -b "$GOBIN" v2.12.2

echo ">>> Go modules"
go mod download

echo ">>> pnpm (via corepack) + UI deps"
corepack enable
corepack prepare pnpm@11.12.0 --activate
(cd dashboard/ui && pnpm install --frozen-lockfile)

cat <<'MSG'

g0efilter dev container ready.

  Dev (API + UI)     : scripts/dev.sh            (add --traffic for demo data)
  Go tests           : scripts/test-go.sh        (or: go test ./...)
  UI tests/lint      : scripts/test-ui.sh
  e2e (docker)       : scripts/e2e.sh            (FILTER_MODE=https)
  Go lint            : golangci-lint run ./...
  DB migration       : edit ent/schema, then scripts/gen-migration.sh <name>
  UI type-check/lint : cd dashboard/ui && pnpm check && pnpm lint
  UI build (embed)   : cd dashboard/ui && pnpm build
MSG
