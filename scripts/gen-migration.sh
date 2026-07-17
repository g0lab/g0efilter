#!/usr/bin/env bash
# Generate a versioned Atlas migration from the Ent schema:
#   scripts/gen-migration.sh <name>
# Edit internal/dashboard/store/ent/schema/*.go first, then run this. It
# regenerates the Ent client and diffs the schema against the committed
# migrations, writing a new timestamped .sql file (+ updating atlas.sum).
# Pure Go - no atlas binary required.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ $# -ne 1 ]; then
  echo "usage: scripts/gen-migration.sh <name>" >&2
  exit 1
fi

echo ">>> regenerating ent client"
go generate ./internal/dashboard/store/ent/...

echo ">>> generating migration: $1"
go run -mod=mod internal/dashboard/store/ent/migrate/main.go "$1"

echo ">>> done. new files under internal/dashboard/store/migrations/"
