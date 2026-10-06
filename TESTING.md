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

Docker builds minify external JavaScript before embedding it in the application.
`npm test` checks minifier behavior, preservation of globals/licenses and the
Docker build order. `runtime.spec.cjs` compares served application scripts with
the expected minified output; all browser interactions run against that image.
Use `npm run build:assets` to preview generated files in ignored `.build/js/`
without changing tracked sources. Inline template scripts are left unchanged.

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
| Logs/docs/map | Separate log-filter routes/reset; API-doc scrolling stability; map view/layer/region/filter/motion controls; globe zoom to 128×, full inspection of 29 co-located IPs, group refresh/removal and keyboard focus |
| Authorization | Viewer/Moderator read-only access-management UI and server-side denials; Go handler tests for role/account/token boundaries |

The new backend `*_ui_regression_test.go` files add 51 table-driven handler cases, including log pagination using actual templates. Existing Go service/repository/security tests and JavaScript map/pagination tests remain in place. The browser fixture fails on uncaught JavaScript errors. Error-path UI tests deliberately intercept selected requests; normal lifecycle tests use the real backend. External-source refresh is intercepted so tests never fetch third-party lists.

## Upgrade and API-token compatibility

Log-retention unit tests cover independent 3/12-month limits, invalid configuration,
UTC/month-end/leap-year cutoffs, batch limits, cancellation and query timeouts.
`TestLogRetentionRepository` uses a disposable PostgreSQL container to verify
category-specific deletion, DEFAULT/monthly partitions, exact cutoff boundaries,
duplicate IDs across timestamps, unknown/null actions, locked-row skipping,
idempotence, explorer counts/pagination before deletion, and preserved live blocks.

```sh
go test -short ./internal/models ./internal/config ./internal/service
go test -tags=integration -run '^TestLogRetentionRepository$' -count=1 ./internal/repository
```

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
pages, login, account/role creation and the block dialog at both viewports.
Desktop pages are scanned with both collapsed and expanded navigation; keyboard
focus and exit are checked separately. Scans wait for actual sidebar transitions
to finish, so partially faded text cannot cause timing-dependent contrast failures.
No accessibility rules are disabled, and production animations remain unchanged.
Failure output includes axe's contrast/violation explanation alongside each target.
The suite also checks keyboard sign-in navigation. These detect automated violations;
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

### Entra reauthentication and legacy-account authority

The signed-ID-token tests verify the explicit `auth_time` request, acceptance of
fresh proof, rejection of missing/stale/future proof (even with a fresh `iat`),
nonce/state checks and one-time callback consumption. Callback/session tests
check that fresh verification enables sensitive actions, ordinary SSO does not,
another bound identity or a disabled account is rejected, and failure messages
and audit entries contain only safe diagnostics.

Permission tests cover Editor migration of legacy accounts, recovery-admin
authority, continued rejection of privilege escalation, unchanged token scope
checks and role-backed/Entra accounts remaining explicit. `TestAccountStatus`
checks the same rules inside a disposable PostgreSQL transaction, including
disabled recovery actors and stale authorization snapshots.

```sh
go test -short ./...
go test -tags=integration ./internal/repository -run '^TestAccountStatus$' -count=1 -timeout=5m
```

Live Entra verification still requires the tenant-specific staging checklist in
[ENTRA_SETUP.md](ENTRA_SETUP.md#troubleshooting-identity-verification).

### Entra account-label regression coverage

Entra UPNs are presentation labels, not replacements for account keys. Model and
HTTP/template tests cover local-account fallback, missing or renamed UPNs, HTML
escaping, and unchanged session identity/permissions. A desktop/mobile browser
test creates a bound account whose UPN differs from its key, checks the label and
responsive wrapping, and verifies that role changes and deletion still submit
the original key while the confirmation displays the UPN.

The UPN display update passed 63 targeted browser tests (the desktop-only hover
check is skipped on mobile), all 99 JavaScript unit tests, and API/model Go tests
with race detection. Screenshot baselines were not changed. Full golangci-lint
v2.13.0 passed with zero issues using a ten-minute local timeout after the initial
five-minute run reported zero issues but exceeded its limit during concurrent
browser validation; the CI timeout was not changed.

### Dashboard ranking regression coverage

`tests/dashboard_controls.test.cjs` executes the shipped stats-refresh handler
to check that all ten countries, ASNs and reasons survive repeated refreshes,
use consistent chip classes, escape untrusted labels, and retain prior values
on missing data or request failures.

`tests/e2e/dashboard_insights.spec.cjs` covers initial server rendering using ten
real test blocks, unchanged chip markup after refresh, and the actual 15-second
refresh timer with controlled country/ASN/reason responses. It checks long,
unbroken labels and counts for clipping at 390, 601, 768, 1024, 1440 and 2560px,
failed refreshes, empty states, recovery and populated-ranking accessibility.
All fixtures run in the disposable test stack, never a running deployment.

```sh
npm test
npm run test:ui -- dashboard_insights.spec.cjs operations.spec.cjs visual.spec.cjs
```

Verified on 2026-10-06: all 102 JavaScript unit tests and 32 targeted browser
tests passed. Desktop/mobile ranking screenshots were reviewed; existing visual
baselines were unchanged. The disposable containers and network were removed;
development and production deployments were not modified.

## Account search and status regression coverage

`tests/e2e/account_status.spec.cjs` covers case-insensitive account-name/UPN search,
combined source/status filters, reload persistence, counts, empty results, clearing,
confirmation/cancel, failed changes, stable identity keys, and read-only access.
It exercises real local sign-in, sessions, Basic auth and API tokens through
disable/re-enable, including rejection of old sessions after re-enabling, live
WebSocket closure within the 30-second recheck and system-audit action filtering. Populated
desktop/mobile account tables are checked for accessibility and page overflow.

Go tests in `internal/api/account_status_test.go` and
`internal/service/account_status_test.go` cover request validation, authorization,
protected accounts, status conflicts and disabled authentication paths. The
integration-tagged `internal/repository/account_status_test.go` checks migration
defaults, preservation of credentials/roles/tokens, atomic audit records, session
invalidation, stale authorization, concurrent cross-disable attempts and disabled
Entra invitations/bindings with auto-provisioning on and off.

```sh
go test -short -race ./internal/api ./internal/service ./internal/models
go test -race -tags=integration ./internal/repository ./internal/api
npm run test:ui -- account_status.spec.cjs identity.spec.cjs auth.spec.cjs accessibility.spec.cjs
```

All mutating tests use disposable databases/accounts. They must not target an
existing development, staging or production deployment.

Verified on 2026-10-06: 102 JavaScript unit tests passed; Go API/model/service/
repository short race tests and repository/API integration race tests passed;
the extra stale-role-permission scenario passed in a focused integration rerun.
The browser selection above plus `visual.spec.cjs` passed 61 tests (one desktop-only
check skipped on mobile); the final six account tests passed again with the live
connection and audit-filter assertions. Existing visual baselines were unchanged.
Go lint v2.13.0 with integration tags reported zero issues. Disposable test stacks
were removed; running development and production deployments were untouched.

## What still needs deployment-specific checks

This is regression coverage, **not a guarantee that every possible button, input, or integration works**. Live Microsoft redirects/Conditional Access, real Entra group-role mapping and provisioning, Fail2ban/Fortigate clients, actual webhook delivery, external list downloads, production GeoIP data, email delivery, and other browsers/devices require staging tests with your configuration. Follow [ENTRA_SETUP.md](ENTRA_SETUP.md) for the Microsoft sign-in checklist. Do not point the destructive browser lifecycle tests at staging or production.

## Last local verification: 2026-10-06

- Full browser suite: **99 passed**, 50 desktop and 49 mobile, with screenshot
  updates disabled. The desktop-only hover-rail keyboard check is skipped on
  mobile. This includes 27 accessibility tests, eight visual tests comparing ten
  reviewed PNGs, and actual login-canvas motion/pause checks.
- Reproduced the CI sidebar contrast failure by sampling the label fade halfway
  through its transition; the same labels pass once fully visible. The audit-log
  and keyboard-focus checks then passed five consecutive repetitions each after
  adding transition-aware scanning. No application styling or behavior changed.
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

### Threat-map zoom and group inspection follow-up

- JavaScript unit suite: **112 passed**, including all 29 co-located members,
  nearby-coordinate separation, bounded canvas allocation, refreshed metadata,
  expired-group recovery and the existing 20,000-record count checks.
- Focused browser run: **8 passed** across desktop/mobile map controls,
  navigation, accessibility and group inspection. After the final CSS sizing
  correction, both group tests passed again, including locally scrolling side
  panels and unclipped controls/legend at a 1201×700 desktop viewport.
- The browser runner built the normal Docker image with minified JavaScript.
  Fixtures intercept only their own requests with labelled synthetic records;
  development and production services were not reused or changed.

## Low-risk performance follow-up

This performance package changes in-process work only; it adds no migration,
deployment step, environment variable or data-retention change.

- `/api/v1/raw` and Bloom synchronization read one Redis `HGETALL` snapshot as
  before. A key-only decode path avoids retaining a second metadata map and
  reuses a cleared decode target. It still performs full `IPEntry` decoding:
  malformed/type-invalid records are skipped, and legacy/expired records keep
  the previous semantics. The raw response format and unspecified order remain
  unchanged. Redis payload size and network round-trips are **not** reduced.
- Concurrent forward/PTR cache misses for the same key share one resolver call.
  Different keys proceed independently. The 3-second DNS timeout, 5-minute
  positive TTL, 1-minute empty/error TTL, forced background refresh and
  forward-confirmed reverse DNS checks remain intact.
- Each DNS cache removes expired entries at most once a minute when used, in
  every application process. Untouched expired keys no longer accumulate over
  continued DNS activity. This is not a cap on live entries; an idle cache is
  swept when used again. Cached values are never refreshed merely by reading.
- Bloom synchronization no longer holds its mutex during Redis I/O/decoding,
  and merges in small batches without losing concurrent additions. During a
  sync, negative checks go directly to Redis until the snapshot is merged;
  this temporarily adds individual Redis reads instead of queuing requests
  behind the snapshot. A failed sync leaves existing filter contents intact.

`ip_service_dns_test.go` covers 64 simultaneous same-key requests, independent
keys, positive/empty/error/partial-result TTLs, timeout/retry, cleanup of 10,000
untouched expired keys, forced refresh, exclusion invalidation and spoofed PTR
rejection. `ip_service_bloom_test.go` reproduces a delayed snapshot and verifies
that block checks and new writes continue without losing blocks.
`redis_keys_test.go` compares key-only reads with the previous decoder and
includes a fuzz target; handler tests cover raw text, empty lists, IPv4/IPv6 and
storage errors.

```sh
go test -short -race ./cmd/... ./internal/... -count=1
go test ./internal/repository -run '^$' -fuzz '^FuzzBlockedIPKeysCompatibility$' -fuzztime=20s -parallel=2
go test ./internal/repository -run '^$' -bench '^BenchmarkBlockedIPKeys$' -benchmem -count=5 -cpu=2 -benchtime=1s
```

Local Linux/amd64 results on 2026-10-06 (Go 1.27 container, Ryzen 7 4700U,
`GOMAXPROCS=2`, median of five synthetic runs):

| Records | Previous processing | Key-only processing | Previous allocated bytes | Key-only allocated bytes |
| --- | ---: | ---: | ---: | ---: |
| 10,000 | 43.95 ms | 26.45 ms | 6.48 MB | 1.30 MB |
| 100,000 | 601.62 ms | 282.15 ms | 59.20 MB | 12.88 MB |

The benchmark measures decoding/key collection **after** the identical Redis
snapshot, not HTTP latency, total process RAM or production throughput. Timing
varies with host load; allocated bytes are per operation, not retained memory.
These results do not establish the cause of the reported multi-second webhook
stalls. SQL/pool/lock waits still need measurements during an incident. No auth
cache, async audit writes, shortened timeouts, SQL index or token-use tracking
change is part of this performance package.

Verified locally on 2026-10-06: all Go application packages passed the final
short race-test run in a read-only Linux container; focused raw/DNS/Bloom tests
also passed natively on Windows. The Linux fuzz run passed 48,950 generated
inputs. The delayed-snapshot regression failed against the previous locking
code, then passed with the optimization. Golangci-lint v2.13.0 with integration
tags passed with zero issues in a separate, concurrency-limited run. The initial
concurrent run timed out and reported one test-style finding, which was fixed;
the repeat used a local 10-minute timeout without changing CI configuration.
No running development or production deployment was updated.
