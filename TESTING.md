# Regression tests

Unit tests alone do not prove that a button is connected to its handler. This repository also has Playwright tests that exercise the rendered application, its real HTTP endpoints, and a disposable PostgreSQL/Redis stack.

## Run locally

Prerequisites: the Go version in `go.mod`, Node.js 24, and Docker with Linux containers/Compose v2 running.

```sh
go test -short ./...
npm ci --ignore-scripts
npm test
npm run test:ui
go test -race -tags=integration -count=1 -timeout=15m ./...
```

The runner starts a pinned Playwright Linux browser container; no browser install
on the host is needed. To narrow a run:

```sh
npm run test:ui -- --project=desktop
npm run test:ui -- settings.spec.cjs
npm run test:ui:report
```

The default browser suite runs both a 1440×1000 desktop and a 390×844 touch/mobile Chromium viewport. This is mobile emulation, not a real iOS/Android device or Safari/Firefox validation. The pinned browser image must match the Playwright version in the npm lockfile. Windows and CI share the same Linux browser/fonts, locale and timezone.

GitHub Actions runs frontend unit tests, the browser suite, short Go tests with
the race detector, and a separate integration-tagged race test job. The latter
includes identity/UPN-binding concurrency tests and schema upgrade checks that
an untagged `go test ./...` does not select. Local race detection requires CGO
and a C compiler (or a Linux Go test container).

## Isolation and cleanup

`npm run test:ui` generates a unique `blocklist-e2e-*` Compose project, temporary credentials, a loopback-only random app port, and fresh databases in tmpfs. It does not load the developer's `.env`, connect to the development database, or accept a production URL. Entra authentication, background workers, and outbound webhooks are disabled in this stack.

The runner removes its own containers/network/volumes and temporary authentication files in `finally`, including after test failure. If forcibly killed, inspect `docker compose ls` and clean up **only the exact test project printed by that run**, never the dev/prod project. Docker build cache/images remain reusable. Browser reports and traces are ignored by Git; treat them as sensitive because they can contain disposable test credentials and session cookies. Do not publish them indiscriminately.

## What is exercised

| Area | Checks |
| --- | --- |
| Authentication | Real password/TOTP sign-in, first-time MFA enrollment during fixture setup, invalid credentials, logout, protected routes |
| Candidate runtime | Clean current migration version, health/raw endpoints, embedded logo/OpenAPI assets, unauthenticated and scoped-token API boundaries |
| Login design | All six background choices, pause/play even with reduced-motion settings, saved choice, raw API link target, health link |
| Navigation | Every sidebar destination, expansion across desktop navigation, keyboard navigation, mobile layouts, page-wide overflow |
| Dashboard | Block dialog validation/presets/cancel/submit, details, unblock, bulk selection/cancel/unblock, filters/chips/Clear All, saved views, columns/density, filtered exports, 101-record paging, failed refresh and Retry |
| Lists | Whitelist and exclusion creation, expiry, filtering, delete confirmations, exclusion/block conflict flow, external-source create/delete |
| Roles/accounts | Custom-role lifecycle, permissions/counts/discard, built-in protection, invalid input, visible API errors/reauthentication, local/UPN-only Entra account creation, role assignment/override, password/MFA/delete controls |
| Settings | All four token templates' exact submitted and persisted scopes, scope edits/cancel/revoke, webhook create/delete |
| Logs/docs/map | Separate log-filter routes/reset; API-doc scrolling stability; map view/layer/region/filter/motion controls |
| Authorization | Viewer/Moderator read-only access-management UI and server-side denials; Go handler tests for role/account/token boundaries |

The new backend `*_ui_regression_test.go` files add 51 table-driven handler cases, including log pagination using actual templates. Existing Go service/repository/security tests and JavaScript map/pagination tests remain in place. The browser fixture fails on uncaught JavaScript errors. Error-path UI tests deliberately intercept selected requests; normal lifecycle tests use the real backend. External-source refresh is intercepted so tests never fetch third-party lists.

## Upgrade and API-token compatibility

`TestAPIHandler_UpgradeTokenCompatibility` creates its own PostgreSQL and Redis
containers, seeds schema 16 with synthetic legacy accounts/tokens/data, and
applies the current migrations. It verifies that token hashes, scopes, source-IP
restrictions, expiry, password/MFA data, saved views, blocks and logs survive.
A second migration run must be a no-op.

`TestSchema16Upgrade` additionally checks the repository and authentication service
directly against persisted schema-16 blocks and expiring/unlimited tokens after
the current migrations run. Both upgrade suites use disposable databases.

Requests then go through the real HTTP routes and repositories: Fortigate-style
raw/JSON whitelist reads and Basic Auth; Fail2ban/Graylog-style block/unblock;
last-use tracking; expired/revoked tokens; deleted owners; source-IP restrictions
(including forged forwarding headers); read-only and empty scopes; and immediate
permission reduction after an owner's role changes. System-listed tokens use the
same authentication path as personal tokens. No real integration token is used.

```sh
go test -tags=integration -run '^TestAPIHandler_UpgradeTokenCompatibility$' -count=1 ./internal/api
```

## Accessibility and visual checks

The browser suite runs axe WCAG 2 A/AA and 2.1 A/AA checks on all ten authenticated
pages, login, account/role creation and the block dialog at both viewports. It
also checks keyboard sign-in navigation. These detect automated violations;
screen-reader usability and complete WCAG conformance still need human review.

Ten committed screenshots cover deterministic login, role, local/Entra account
and block-dialog surfaces. Animation is frozen only while taking screenshots;
separate interaction tests continue to exercise real animation/pause behavior.
Missing baselines fail CI. To deliberately update them after a reviewed change:

```sh
npm run test:ui -- visual.spec.cjs --update-snapshots
npm run test:ui -- visual.spec.cjs
```

Inspect every changed PNG in `tests/e2e/snapshots/` before committing. Do not
accept snapshots just to clear a failure. Use the pinned Linux browser image
for updates and verification so local fonts/rendering match CI.

The production-image pipeline runs these checks again against the exact scanned
candidate digest. See [.github/RELEASING.md](.github/RELEASING.md) for approval,
environment protection and rollback instructions.

## What still needs deployment-specific checks

This is regression coverage, **not a guarantee that every possible button, input, or integration works**. Live Microsoft redirects/Conditional Access, real Entra group-role mapping and provisioning, Fail2ban/Fortigate clients, actual webhook delivery, external list downloads, production GeoIP data, email delivery, and other browsers/devices require staging tests with your configuration. Follow [ENTRA_SETUP.md](ENTRA_SETUP.md) for the Microsoft sign-in checklist. Do not point the destructive browser lifecycle tests at staging or production.

## Last local verification: 2026-10-06

- Full browser suite: **98 passed**, 49 desktop and 49 mobile, with screenshot
  updates disabled. This includes 26 accessibility tests, eight visual tests
  comparing ten reviewed PNGs, and actual login-canvas motion/pause checks.
- JavaScript unit suite: **99 passed**, including fail-closed production-policy,
  rollback/promotion and package-cleanup tests from both branches.
- All Go application packages passed with both `-short -race -count=1` and
  `-race -tags=integration -count=1`
  in a Linux Go container, including upgrade/API-token compatibility and the
  51 added handler cases. Source was mounted read-only; databases were disposable.
  The local command used `./cmd/... ./internal/...` (all Go packages) to avoid
  walking browser report directories while the browser runner recreated them.
- Actionlint v1.7.12 with ShellCheck passed on every merged workflow. The
  JavaScript promotion/cleanup tests passed; no registry promotion was run.
- Linux golangci-lint v2.13.0 with integration tags passed with zero issues.
  The initial cold-cache run timed out while other validation was running;
  the same five-minute command passed after cache warmup and workload completion.
- Full-history Gitleaks passed across 519 commits with inline waivers disabled
  and the reviewed retired-test-secret fingerprint exception retained.
- No development or production deployment was changed. GitHub-hosted release
  execution, protected-environment configuration and registry publication still
  need to be verified after pushing. The retired historical test-secret exception
  is documented in [.github/SECURITY_CHECKS.md](.github/SECURITY_CHECKS.md).
- The disposable browser containers/network and temporary authentication files
  were removed after the final successful run.
