# Approving a production image

`Docker Build and Check` builds on pushes to every branch and
can also be started through **Actions → Docker Build and Check → Run workflow**.
Building is automatic; publishing `latest` requires a separate human approval.
This workflow updates GHCR image tags. It does not connect to or restart production.
An external auto-updater may deploy a changed tag; check your host configuration.

## Configure GitHub before merging

Finish or cancel any still-running legacy Docker publication jobs before the
cutover. New approval rules do not retroactively protect runs using the old
auto-publication workflow.

In **Settings → Environments → production**:

1. Add at least one **Required reviewer** (for example, `arumes31`).
2. Disable **Allow administrators to bypass configured protection rules**.
3. Under deployment branches and tags, choose **Selected branches and tags**.
   Add exactly one rule: type **Branch**, name **main**. No tag or wildcard rules.
4. Leave **Prevent self-review** off only if the person starting the workflow must
   also approve it. Otherwise enable it and appoint another reviewer.

The workflow verifies these settings and fails closed if they are absent,
unreadable, or weaker than the policy. Creating an environment without reviewers
does not create an approval gate. The repository's GitHub plan must support
required reviewers; GitHub offers this for public repositories on current plans.

Only the automatic `GITHUB_TOKEN` is used for GHCR. Keep package write access
enabled for this repository's publishing jobs; no PAT, SSH key, production
password, Entra secret, or database credential is needed.

Configure the main branch ruleset to require pull requests, workflow/CODEOWNERS
review, and the quality/security checks. CodeQL and PR dependency review remain
separate branch-protection checks; they are not synchronous image-pipeline jobs.

## What must pass

1. Reusable Go CI: unit/race tests, explicit integration-tagged PostgreSQL/Redis
   tests, schema-16 upgrade and API-token compatibility tests, frontend tests,
   desktop/mobile interactions, accessibility checks and visual baselines, lint.
2. Reusable Security: gosec, govulncheck and redacted full-history Gitleaks.
3. Build a uniquely tagged `candidate-<commit>-<run>-<attempt>` image with SBOM
   and provenance, then scan its exact digest with Trivy (fixable HIGH/CRITICAL).
4. Pull that digest, without rebuilding it, into a new disposable test stack.
   Run the browser/API suite against its actual binary, embedded assets and
   migrations. This uses synthetic credentials, no production data or services.

The source-level upgrade suite populates schema 16 before applying current
migrations. The candidate runtime suite separately verifies clean startup and
real HTTP/browser behavior. Neither is a restore rehearsal of your production
backup or a live Fortigate/Fail2ban/Entra deployment test.

Active or unreviewed security findings must be resolved before release. The
historical example credential documented in [SECURITY_CHECKS.md](SECURITY_CHECKS.md)
has a fingerprint-only exception after the maintainer confirmed on 2026-10-06
that it was a test secret and is no longer in use. Full-history secret scanning
remains required; this exception does not waive other findings.

## Publish main to latest

### JavaScript in image builds

Every Docker image build (including GitHub Actions and the disposable browser
tests) runs `npm ci --ignore-scripts` and `npm run build:assets` in a separate,
digest-pinned Node.js stage. The locked Terser version removes unnecessary
whitespace/comments while preserving license notices, identifiers and classic
script behavior. Already compact files are never replaced with larger output.
Generated files keep their original URLs and are copied into the Go build before
`go:embed`; Node.js and npm dependencies are not included in the runtime image.

Tracked JavaScript is unchanged. For a local preview, run `npm ci --ignore-scripts`
then `npm run build:assets`; output goes to ignored `.build/js/`. Syntax errors
fail the build. Frontend tests cover minifier contracts and the browser suite
checks that the built image actually serves the generated files. Inline scripts
in Go HTML templates are not rewritten. See [Terser options](https://terser.org/docs/api-reference/).

### Approval steps

1. Open the completed candidate run in Actions. Review the exact commit and image
   digest in its job summary and ensure all prerequisite jobs passed.
2. Choose **Review deployments → production → Approve and deploy**.
3. The promotion job checks that this commit is still the current main head.
   If main advanced while waiting, approve the newer successful run instead.
4. Promotion copies the tested digest to `main`, `latest`, and the full commit
   SHA tag. No rebuild occurs. The job verifies every final tag resolves to that
   digest and saves an `image-digest-*` artifact for 90 days.

Registry tag updates are not transactional. If promotion fails after a write,
inspect the publication record and current tag digests before retrying; do not
assume a failed job means every tag stayed unchanged.

Only `main` can publish container images. Other branches, including `test` and
`v2b_test`, build and scan locally on the runner without pushing any image tags.
Manual runs follow the same restriction. `v*` binary releases remain in the
separate GoReleaser workflow and do not publish container tags.

The image pipeline and package cleanup share one concurrency group; they cannot
race each other and are not cancelled mid-publication by a newer push. GitHub
concurrency is not a durable FIFO queue: a newer pending run may supersede an
older pending run. Review the actual run and commit rather than assuming every
push will become a release.

## Rollback and cleanup

### Log retention rollout

Before deploying this image, review/export required historical logs. The new defaults
are **3 calendar months for event logs** and **12 for system audit logs**. Configure
`EVENT_LOG_RETENTION_MONTHS` (1–3) and `AUDIT_LOG_RETENTION_MONTHS` (1–12) consistently
on all server and worker replicas. Invalid values fail startup; these settings need
a process/container restart and are not editable in the UI. This feature adds no
schema migration or index build.

Old records disappear from the log explorers immediately and are **irreversibly
deleted** in bounded background batches starting when the maintenance scheduler
starts. Monitor category/deleted counts and timeout/failure messages during backlog
cleanup; do not assume all expired rows are removed in the first cycle. Ensure an
in-process or standalone worker is running. The old `LOG_RETENTION_MONTHS` now
applies only to webhook-payload partitions, not the shared audit/event table.
An image rollback or a longer retention setting cannot restore deleted history.
An older image can also resume its old shared-partition deletion policy.
See [retention configuration](../README.md#event-and-system-audit-retention).

### Image rollback

Before moving `latest`, the job copies its previous digest to `rollback` and
records that digest in `publication.json` in the publication artifact. Retrying
an already-published digest preserves the existing rollback target. Use the
recorded `image@sha256:...` reference for a deterministic host rollback.
**An image rollback does not undo database migrations**; check schema
compatibility and keep a tested DB backup.

Account-status migration `000018_account_status` keeps all existing accounts
enabled. Once accounts are disabled, **older images do not enforce their disabled
status**, even if this column remains in the database. Rolling back the migration
also removes disabled status. Review these access implications before rollback;
see [account status](../README.md#account-search-and-access-status).

The package-cleanup workflow runs only from `main`, defaults to dry run, and
protects production/test aliases, rollback, all candidate and release tags, and
untagged manifests that may belong to a protected image. It keeps the ten newest
versions; other eligible tagged versions must be over 30 days old and are
rechecked immediately before deletion. Candidates are intentionally retained
while they might be awaiting approval. Retire obsolete candidates explicitly in
GHCR only after checking that their runs are finished/rejected and no deployment
or rollback depends on them. A missing candidate must be rebuilt and retested.

References: [GitHub approval rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[reviewing deployments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments),
[digest promotion](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/).
