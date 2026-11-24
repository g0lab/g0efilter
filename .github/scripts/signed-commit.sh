#!/usr/bin/env bash
# Commits the staged index of the current checkout to a branch through the GitHub API:
#
#   signed-commit.sh <branch> <message>
#
# GitHub signs a commit it creates for a bot token when the request sets no author or
# committer; a `git commit` pushed from a runner is unsigned. The parent is HEAD, or none
# when HEAD is unborn. A missing branch is created; an existing one is only fast-forwarded.
# Needs GH_TOKEN with contents: write.
set -euo pipefail

die() {
  echo "$*" >&2
  exit 1
}

[ "$#" -eq 2 ] || die "usage: signed-commit.sh <branch> <message>"
branch="$1"
message="$2"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

parent="$(git rev-parse --verify --quiet HEAD || true)"
if [ -n "$parent" ]; then
  base="$(git rev-parse "$parent^{tree}")"
else
  base="$(git hash-object -t tree /dev/null)"
fi

: > "$work/entries"
while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
  read -r old_mode new_mode _ sha status <<< "${meta#:}"
  if [ "$status" = D ]; then
    jq -cn --arg path "$path" --arg mode "$old_mode" \
      '{path: $path, mode: $mode, type: "blob", sha: null}' >> "$work/entries"
    continue
  fi
  git cat-file blob "$sha" | base64 -w0 > "$work/blob"
  uploaded="$(jq -n --rawfile content "$work/blob" '{content: $content, encoding: "base64"}' |
    gh api "repos/$repo/git/blobs" --input - --jq .sha)"
  [ "$uploaded" = "$sha" ] || die "$path uploaded as $uploaded, expected $sha"
  jq -cn --arg path "$path" --arg mode "$new_mode" --arg sha "$sha" \
    '{path: $path, mode: $mode, type: "blob", sha: $sha}' >> "$work/entries"
done < <(git diff --cached --no-renames --no-abbrev --raw -z "$base")

[ -s "$work/entries" ] || die "nothing staged to commit"

tree="$(jq -s --arg base "$base" --arg parent "$parent" \
  '{tree: .} + (if $parent == "" then {} else {base_tree: $base} end)' \
  "$work/entries" | gh api "repos/$repo/git/trees" --input - --jq .sha)"
# Git objects are content-addressed, so equal SHAs prove GitHub holds exactly the index.
[ "$tree" = "$(git write-tree)" ] || die "GitHub built tree $tree, but the index is $(git write-tree)"

jq -n --arg message "$message" --arg tree "$tree" --arg parent "$parent" \
  '{message: $message, tree: $tree, parents: (if $parent == "" then [] else [$parent] end)}' |
  gh api "repos/$repo/git/commits" --input - > "$work/commit"
commit="$(jq -r .sha "$work/commit")"
if [ "$(jq -r .verification.verified "$work/commit")" != true ]; then
  die "GitHub did not sign $commit: $(jq -r .verification.reason "$work/commit")"
fi

if gh api "repos/$repo/git/ref/heads/$branch" --silent 2> /dev/null; then
  gh api --method PATCH "repos/$repo/git/refs/heads/$branch" \
    -f sha="$commit" -F force=false --silent
else
  gh api "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$commit" --silent
fi
echo "$commit"
