#!/usr/bin/env bash
# Delete Actions artifacts older than ARTIFACT_MAX_AGE_DAYS. A backstop for uploads that forget
# `retention-days`; the workflows that upload set it themselves, so a clean repo deletes nothing.
#
# Requires: curl and jq, both present on ubuntu-latest. Needs a token with
# `actions: write`. Set DRY_RUN=true to log the candidates without deleting.
set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

api="${GITHUB_API_URL:-https://api.github.com}"
max_age_days="${ARTIFACT_MAX_AGE_DAYS:-1}"
dry_run="${DRY_RUN:-false}"
cutoff=$(( $(date -u +%s) - max_age_days * 86400 ))

call() {
  curl --silent --show-error --fail-with-body \
    --header "Authorization: Bearer ${GITHUB_TOKEN}" \
    --header "Accept: application/vnd.github+json" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "$@"
}

# Collect every page before deleting: removing artifacts mid-walk reshuffles later pages.
candidates=$(
  page=1
  while :; do
    body=$(call "${api}/repos/${GITHUB_REPOSITORY}/actions/artifacts?per_page=100&page=${page}")
    count=$(jq '.artifacts | length' <<<"$body")
    jq -r --argjson cutoff "$cutoff" '
      .artifacts[]
      | select(.expired | not)
      | select((.created_at | fromdateiso8601) < $cutoff)
      | "\(.id)\t\(.created_at)\t\(.size_in_bytes)\t\(.name)"
    ' <<<"$body"
    [ "$count" -eq 100 ] || break
    page=$(( page + 1 ))
  done
)

if [ -z "$candidates" ]; then
  echo "No unexpired artifacts older than ${max_age_days}d in ${GITHUB_REPOSITORY}."
  exit 0
fi

total=$(wc -l <<<"$candidates")
bytes=$(awk -F'\t' '{ sum += $3 } END { print sum + 0 }' <<<"$candidates")
echo "Found ${total} artifact(s) older than ${max_age_days}d, ${bytes} bytes:"

failed=0
while IFS=$'\t' read -r id created size name; do
  if [ "$dry_run" = "true" ]; then
    echo "  would delete ${id} ${created} ${size}B ${name}"
    continue
  fi
  echo "  deleting ${id} ${created} ${size}B ${name}"
  # A concurrent expiry turns the artifact into a 404; that is the desired end state either way.
  if ! call --request DELETE --output /dev/null \
    "${api}/repos/${GITHUB_REPOSITORY}/actions/artifacts/${id}"; then
    echo "::warning::failed to delete artifact ${id} (${name})"
    failed=$(( failed + 1 ))
  fi
done <<<"$candidates"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Artifact prune"
    echo
    echo "- Repository: \`${GITHUB_REPOSITORY}\`"
    echo "- Older than: ${max_age_days} day(s)"
    echo "- Matched: ${total} artifact(s), ${bytes} bytes"
    echo "- Dry run: ${dry_run}"
    # A bare `[ ] && echo` here would end the group non-zero and trip `set -e` on a clean run.
    if [ "$failed" -gt 0 ]; then echo "- Failed: ${failed}"; fi
  } >>"$GITHUB_STEP_SUMMARY"
fi

[ "$failed" -eq 0 ]
