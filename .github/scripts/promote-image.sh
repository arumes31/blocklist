#!/usr/bin/env bash
set -euo pipefail
[[ "$IMAGE" == "ghcr.io/${GITHUB_REPOSITORY,,}" ]]
[[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ ]]
case "$GITHUB_REF" in
  refs/heads/main) aliases=(main latest "$GITHUB_SHA") ;;
  refs/heads/test) aliases=(test "$GITHUB_SHA") ;;
  refs/heads/v2b_test) aliases=(v2b_test "$GITHUB_SHA") ;;
  *) echo 'Unsupported image publication ref' >&2; exit 1 ;;
esac

previous=none
if [[ "$GITHUB_REF" == refs/heads/main ]]; then
  if output=$(docker buildx imagetools inspect "$IMAGE:latest" 2>&1); then
    previous=$(awk '/^Digest:/ {print $2; exit}' <<< "$output")
    [[ "$previous" =~ ^sha256:[a-f0-9]{64}$ ]]
  elif ! grep -Eqi 'manifest unknown|no such manifest|:[[:space:]]*not found' <<< "$output"; then
    printf '%s\n' "$output" >&2
    exit 1
  fi
fi

tags=$(printf '%s\n' "${aliases[@]}" | jq -R . | jq -s .)
jq -n --arg image "$IMAGE" --arg digest "$DIGEST" --arg previous "$previous" \
  --arg commit "$GITHUB_SHA" --argjson tags "$tags" \
  '{image:$image,digest:$digest,previous_digest:$previous,commit:$commit,tags:$tags,verified:false}' > image-metadata.json

if [[ "$previous" != none ]]; then
  docker buildx imagetools create --prefer-index=false --tag "$IMAGE:rollback" "$IMAGE@$previous"
  [[ "$(docker buildx imagetools inspect "$IMAGE:rollback" --format '{{.Manifest.Digest}}')" == "$previous" ]]
fi
args=()
for alias in "${aliases[@]}"; do args+=(--tag "$IMAGE:$alias"); done
docker buildx imagetools create --prefer-index=false "${args[@]}" "$IMAGE@$DIGEST"
for alias in "${aliases[@]}"; do
  for attempt in 1 2 3 4 5; do
    actual=$(docker buildx imagetools inspect "$IMAGE:$alias" --format '{{.Manifest.Digest}}')
    [[ "$actual" == "$DIGEST" ]] && break
    if [[ "$attempt" == 5 ]]; then echo "Alias verification failed: $alias" >&2; exit 1; fi
    sleep "$attempt"
  done
done
jq '.verified = true' image-metadata.json > image-metadata.tmp
mv image-metadata.tmp image-metadata.json
printf '### Published tested image\n\n`%s@%s`\n\nPrevious latest: `%s`\n' \
  "$IMAGE" "$DIGEST" "$previous" >> "$GITHUB_STEP_SUMMARY"
