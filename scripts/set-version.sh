#!/usr/bin/env bash
# Sets the release version everywhere it is pinned:
#   scripts/set-version.sh         # next patch version
#   scripts/set-version.sh 0.9.0   # explicit newer version
#
# VERSION holds plain SemVer. Image tags, Kustomize `?ref=` and the git tag carry a
# v prefix; Helm's appVersion and chart version do not.
# tests/repo/version_test.go fails the build if anything drifts from VERSION.
set -euo pipefail
LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Every chart under deploy/helm is released.
CHARTS=(deploy/helm/*/Chart.yaml)

OLD="$(tr -d '[:space:]' < VERSION)"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! "$OLD" =~ $SEMVER_RE ]]; then
  echo "::error::VERSION must contain plain SemVer (got '$OLD')" >&2
  exit 1
fi

increment_decimal() {
  local number="$1" result="" digit index

  for ((index = ${#number} - 1; index >= 0; index--)); do
    digit="${number:index:1}"
    if [ "$digit" = 9 ]; then
      result="0$result"
      continue
    fi

    printf '%s%s\n' "${number:0:index}" "$((digit + 1))$result"
    return
  done

  printf '1%s\n' "$result"
}

version_is_newer() {
  local candidate="$1" current="$2" index
  local -a candidate_parts current_parts
  IFS=. read -r -a candidate_parts <<< "$candidate"
  IFS=. read -r -a current_parts <<< "$current"

  for index in 0 1 2; do
    if ((${#candidate_parts[index]} > ${#current_parts[index]})); then
      return 0
    fi
    if ((${#candidate_parts[index]} < ${#current_parts[index]})); then
      return 1
    fi
    if [[ "${candidate_parts[index]}" > "${current_parts[index]}" ]]; then
      return 0
    fi
    if [[ "${candidate_parts[index]}" < "${current_parts[index]}" ]]; then
      return 1
    fi
  done

  return 1
}

if (($# > 1)); then
  echo "usage: scripts/set-version.sh [X.Y.Z]" >&2
  exit 1
fi

RAW="${1:-}"
if [ -z "$RAW" ]; then
  IFS=. read -r major minor patch <<< "$OLD"
  NEW="$major.$minor.$(increment_decimal "$patch")"
else
  NEW="${RAW#v}"
fi

if [[ ! "$NEW" =~ $SEMVER_RE ]]; then
  echo "::error::version must look like 1.2.3 (got '$RAW')" >&2
  exit 1
fi

if ! version_is_newer "$NEW" "$OLD"; then
  echo "::error::version $NEW must be newer than VERSION ($OLD)" >&2
  exit 1
fi

echo "$NEW" > VERSION

# Matched on the surrounding context so prose is left alone: "g0efilter v0.8.0 or
# later" states when a requirement began and must not move with the release.
while IFS= read -r file; do
  [ -f "$file" ] || continue
  sed -i \
    -e "s|\(g0lab/g0efilter[a-z-]*:\)v$OLD|\1v$NEW|g" \
    -e "s|\(g0lab/g0efilter/v\)$OLD|\1$NEW|g" \
    -e "s|\(?ref=\)v$OLD|\1v$NEW|g" \
    -e "s|\(newTag: \)v$OLD|\1v$NEW|g" \
    -e "s|\(tag: \)v$OLD|\1v$NEW|g" \
    -e "s|\(appVersion: \)'\?v\?$OLD'\?|\1'$NEW'|g" \
    "$file"
done < <(git ls-files 'deploy/**' 'docs/**' 'examples/**' 'controller/**' README.md)

# Keep the charts and application release aligned. ct still verifies that a chart
# change is accompanied by a version change.
for chart in "${CHARTS[@]}"; do
  chart_old="$(sed -n 's|^version: *||p' "$chart")"
  sed -i "s|^version: $chart_old\$|version: $NEW|" "$chart"
done
while IFS= read -r consumer; do
  sed -i "/^[[:space:]]*- name: g0efilter\$/,/^[[:space:]]*repository:/ {
    s|^\([[:space:]]*version: \).*$|\1$NEW|
  }" "$consumer"
done < <(git ls-files '**/Chart.yaml')

echo "set $OLD -> $NEW across ${#CHARTS[@]} charts"
git --no-pager diff --stat
