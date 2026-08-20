#!/usr/bin/env bash
# Runs every Go fuzz target in turn. Go fuzzes one target at a time, so the total
# runtime is FUZZTIME multiplied by the number of targets.
#
#   scripts/test-fuzz.sh                     # short smoke run
#   FUZZTIME=5m scripts/test-fuzz.sh         # longer campaign
#   FUZZTIME=2m scripts/test-fuzz.sh filter  # only packages matching "filter"
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FUZZTIME="${FUZZTIME:-20s}"
FILTER="${1:-}"

# Modules holding fuzz targets. go list scopes each one, so nested modules are not
# walked twice.
MODULES=("agent" "controller" "dashboard" "shared")

failed=0

fuzz_package() {
  local module="$1" dir="$2" importpath="$3" targets target

  targets="$(grep -ho '^func Fuzz[A-Za-z0-9_]*' "$dir"/*_test.go 2>/dev/null | sed 's/^func //' | sort -u || true)"

  for target in $targets; do
    echo ">>> $importpath: $target ($FUZZTIME)"

    if ! (cd "$module" && GOWORK=off go test "$importpath" -run '^$' -fuzz "^${target}\$" -fuzztime="$FUZZTIME"); then
      failed=$((failed + 1))
    fi
  done
}

for module in "${MODULES[@]}"; do
  while IFS=$'\t' read -r dir importpath; do
    if [ -n "$FILTER" ] && [[ "$importpath" != *"$FILTER"* ]]; then
      continue
    fi

    fuzz_package "$module" "$dir" "$importpath"
  done < <(cd "$module" && GOWORK=off go list -f '{{.Dir}}	{{.ImportPath}}' ./...)
done

if [ "$failed" -ne 0 ]; then
  echo "$failed fuzz target(s) failed; the reproducing input is under testdata/fuzz/"
  exit 1
fi

echo "all fuzz targets passed"
