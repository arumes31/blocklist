#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
export COMPOSE_PROJECT_NAME="blocklist-ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
export CI_SESSION_KEY
export CI_ADMIN_PASSWORD
CI_SESSION_KEY="$(openssl rand -hex 32)"
CI_ADMIN_PASSWORD="$(openssl rand -hex 24)"
compose=(docker compose -f scripts/ci/compose.yml)
mkdir -p tests/e2e/test-results
cleanup() {
  result=$?
  trap - EXIT
  if (( result != 0 )); then
    # Passwords are random; redact them even in disposable-stack diagnostics.
    "${compose[@]}" logs --no-color 2>&1 | sed -e "s/$CI_ADMIN_PASSWORD/[REDACTED]/g" -e "s/$CI_SESSION_KEY/[REDACTED]/g" > tests/e2e/test-results/stack.log || true
  fi
  "${compose[@]}" down --volumes --remove-orphans || true
  exit "$result"
}
trap cleanup EXIT
if [[ "$CANDIDATE_IMAGE" == ghcr.io/* ]]; then
  [[ "$CANDIDATE_IMAGE" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Candidate must be an immutable digest'; exit 1; }
  docker pull "$CANDIDATE_IMAGE"
fi
"${compose[@]}" up --detach --wait --wait-timeout 180 --no-build
# The real application must have successfully applied every embedded migration.
expected=$(find cmd/server/migrations -name '*.up.sql' -printf '%f\n' | sort | tail -1 | cut -d_ -f1)
actual=$("${compose[@]}" exec -T postgres psql -U ci -d blocklist -Atc 'SELECT version FROM schema_migrations WHERE NOT dirty')
[[ "$actual" == "$((10#$expected))" ]]
export CI_API_TOKEN="bl_$(openssl rand -hex 24)"
token_hash=$(printf '%s' "$CI_API_TOKEN" | sha256sum | cut -d' ' -f1)
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U ci -d blocklist -c \
  "INSERT INTO api_tokens (token_hash, name, username, role, permissions, allowed_ips) VALUES ('$token_hash', 'runtime-fixture', 'ci-admin', 'viewer', 'view_ips', '')"
cd tests/e2e
npm test -- "$@"
