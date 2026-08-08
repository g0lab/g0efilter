#!/usr/bin/env bash
# Sets the release version everywhere it is pinned:
#   scripts/set-version.sh 0.9.0
#
# VERSION holds plain SemVer. Image tags, Kustomize `?ref=` and the git tag carry a
# v prefix; Helm's appVersion and chart version do not.
# tests/repo/version_test.go fails the build if anything drifts from VERSION.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Every chart under deploy/helm is released.
CHARTS=(deploy/helm/*/Chart.yaml)

NEW="${1:-}"
if [ -z "$NEW" ]; then
  echo "usage: scripts/set-version.sh X.Y.Z" >&2
  exit 1
fi

NEW="${NEW#v}"
if [[ ! "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::version must look like 1.2.3 (got '$1')"
  exit 1
fi

OLD="$(tr -d '[:space:]' < VERSION)"
if [ "$OLD" = "$NEW" ]; then
  echo "already at $NEW"
  exit 0
fi

echo "$NEW" > VERSION

# Matched on the surrounding context so prose is left alone: "g0efilter v0.8.0 or
# later" states when a requirement began and must not move with the release.
while IFS= read -r file; do
  [ -f "$file" ] || continue
  sed -i \
    -e "s|\(g0lab/g0efilter[a-z-]*:\)v$OLD|\1v$NEW|g" \
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
