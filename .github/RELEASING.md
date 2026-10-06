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

Before moving `latest`, the job copies its previous digest to `rollback` and
records that digest in `publication.json` in the publication artifact. Retrying
an already-published digest preserves the existing rollback target. Use the
recorded `image@sha256:...` reference for a deterministic host rollback.
**An image rollback does not undo database migrations**; check schema
compatibility and keep a tested DB backup.

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
