# Security and quality checks

The checks run independently so a failed test or scanner does not prevent the
other tools from reporting. They use GitHub-hosted runners and the automatic
`GITHUB_TOKEN`; do not add production credentials to these workflows.

| Workflow | Checks | Triggers |
| --- | --- | --- |
| Go CI | Frontend unit tests, isolated desktop/mobile interaction/accessibility/visual checks, build, unit/integration race tests, upgrade/token compatibility, module checksum verification, golangci-lint, actionlint | Branch pushes, pull requests, manual |
| Security | gosec with code-scanning results, govulncheck, redacted Gitleaks history scan | Branch pushes, pull requests, daily, manual |
| Dependency Review | Reject newly introduced runtime/development dependencies with low-or-higher known vulnerabilities | Pull requests |
| CodeQL | Go and JavaScript/TypeScript analysis | Branch pushes except Dependabot, all pull requests, weekly, manual |
| Daily Security Scan | Existing Trivy filesystem vulnerability scan | Pull requests, daily, manual |

Dependabot updates cover Go modules, Docker images, GitHub Actions, and the npm
browser-test dependencies. The Docker workflow now calls Go CI and Security as
required jobs before building a candidate. See [RELEASING.md](RELEASING.md) for
manual production approval and exact-digest runtime validation. The binary
GoReleaser workflow is unchanged.
See [TESTING.md](../TESTING.md) for browser-test isolation, commands, and coverage limits.

## GitHub repository setup

After pushing these files:

1. Enable the dependency graph and verify that code scanning is enabled. Dependency
   review is available for public repositories; private repositories require the
   applicable GitHub security license.
2. After the first PR run, select the checks above as required status checks in
   the `main` branch ruleset. Include both CodeQL language checks and the Trivy
   filesystem check. Require pull requests and CODEOWNERS review for workflow
   changes; the existing CODEOWNERS file covers `.github/`.
3. Enable GitHub secret scanning and push protection where available. Gitleaks
   detects secrets after a push; it cannot prevent that initial disclosure.
4. Review the Actions and Security tabs for results. Scheduled runs use workflows
   on the default branch, so the schedules become active after merging there.

These YAML files do not configure repository rulesets or environment settings.
The image workflow explicitly requires its reusable quality/security jobs and
its image scan/runtime tests to pass. Its production promotion job additionally
checks the protected environment configuration. Independent CodeQL and PR-only
dependency review must still be required in the main branch ruleset.

## Local checks

Use the Go version in `go.mod`, and golangci-lint v2.13.0 (matching Go CI):

```sh
go mod verify
golangci-lint config verify
golangci-lint run --build-tags integration --timeout=5m ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
go run github.com/zricethezav/gitleaks/v8@v8.30.1 git --config=.gitleaks.toml --redact --no-banner --ignore-gitleaks-allow --log-opts="--all --full-history" .
go test -race -tags=integration -count=1 -timeout=15m ./...
```

Actionlint only runs its ShellCheck integration when ShellCheck is installed.
Ubuntu GitHub runners include it; a local Go-only run may miss shell findings.
To match CI locally, use the pinned official image, which includes ShellCheck:

```sh
docker run --rm --network none -v "$(pwd)/.github:/repo/.github:ro" --workdir /repo --entrypoint sh rhysd/actionlint:1.7.12 -c 'actionlint .github/workflows/*.yml'
```

Gitleaks scans reachable Git history, not ignored local `.env` files. Deleted
credentials can therefore still fail the check. If a finding is real, revoke or
rotate it first; deleting the current file does not remove historical exposure.
Review false positives individually and document any narrowly scoped exception.
Do not disable a scanner or baseline all findings merely to obtain a green check.
Inline `gitleaks:allow` comments are ignored. Exceptions must be reviewed in the
central configuration or exact-fingerprint ignore file.

`.gitleaks.toml` extends the default detection rules and allows only three exact
dummy values in their specific documentation or test files. It does not exempt
whole files, tests, or commits.

### Reviewed historical test-secret exception

The history review identified an example admin-token fallback in
`cmd/server/main.go:127` at commit
`b596da9f63eb51a7e21c3638725ebb3bfb61f7b1`. On 2026-10-06, the maintainer confirmed
that this was a test secret and is no longer in use. The fallback is absent from
the current source. This confirmation is the basis for the exception; no
production credential inspection or rotation was performed as part of it.

The root `.gitleaksignore` exempts only that finding's exact fingerprint
(commit, path, rule and line). The secret value is not copied into the exception,
and the full-history scan remains required. Other findings, including a secret
reintroduced in a new commit, remain subject to scanning. Reassess this exception
if the maintainer's confirmation changes.

govulncheck fails on reachable vulnerabilities; Trivy also checks dependencies
that may not be reachable. Existing justified Trivy exceptions remain in
`.trivyignore` and should be re-reviewed on dependency updates.

GitHub Actions are pinned to full commit SHAs. CLI tool versions are explicit in
the workflows; review and update those pins separately, since the existing
Dependabot configuration does not update versions embedded in shell commands.

References: [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use),
[dependency review](https://github.com/actions/dependency-review-action),
[Gitleaks](https://github.com/gitleaks/gitleaks).
