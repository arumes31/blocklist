# Blocklist Roadmap

Status legend
- [x] Done
- [ ] Planned / Not started
- [~] In progress

Guiding objectives (2026 H1)
- Security-first: harden auth flows, secrets, and web surface
- Operability at scale: 50k+ entries responsive UI, low-latency APIs
- Clear contracts: documented APIs (OpenAPI), stable feeds, integration adapters
- Observability: measurable SLOs and dashboards

Milestones
- M1 (Weeks 1–3): Core security + pagination/indices (Minimal viable hardened platform)
- M2 (Weeks 4–7): Advanced filters, exports, structured logging, metrics
- M3 (Weeks 8–10): RBAC + API tokens, adapters, OpenAPI, rollout playbooks

---

Security and access control
- [x] Session hardening (Secure/HttpOnly/SameSite cookies)
- [x] Security headers middleware (CSP/Referrer-Policy/XFO/XCTO)
- [x] Basic CSRF (Origin/Referer) for unsafe methods
- [ ] Webhook HMAC signatures with timestamp/nonce and optional mTLS
- [ ] RBAC roles (viewer/operator/admin) and scoped API tokens (phase 1 scaffolding next)
- [x] WebSocket auth + origin checks + compression

Performance and scalability
- [x] Server-side pagination & search (/api/ips)
- [x] Stats endpoint (/api/stats)
- [x] Redis indices & counters (ZSET ips_by_ts, stats counters)
- [x] Atomic Redis writes (Lua) for block/unblock (hash, ZSET, counters)
- [x] Stable ZSET cursor (score:member) in place

UX and UI
- [x] Virtualized/incremental loading and debounced server-side search
- [x] Live status controls; animations for new entries
- [x] Stats display (hour/day/total/top countries)
- [x] Advanced filters UI (chips, URL state, country/added_by/date range)
- [ ] Saved views per user, bulk actions, exports (CSV/NDJSON)
- [ ] Accessibility enhancements

Data enrichment and analytics
- [ ] ASN enrichment and top ASNs
- [ ] Reason taxonomy and top reasons
- [ ] Correlation/deduplication and TTL visibility/editing

API and integrations
- [x] OpenAPI scaffolding (/openapi.json) and readiness (/ready)
- [x] Expand OpenAPI spec; add Swagger UI scaffolding (/docs)
- [ ] Source adapters (Fail2ban/Suricata/WAF) and outbound webhooks with retries
- [ ] ETag/delta feeds

Observability and operations
- [x] Prometheus counters (blocks/unblocks)
- [x] Histograms for HTTP latency and Redis ops
- [x] Readiness endpoint with dependency detail

Reliability and retention
- [ ] TTL sweepers/retention policies; HA options documentation

Deployment and supply chain
- [~] Alpine hardened image, non-root; pinned digests; SBOM; CI scans

Testing
- [ ] Unit/integration tests (Redis testcontainers), fuzz tests, load tests

Acceptance criteria (added)
- [x] Advanced filters: filters reflected in URL, applied server-side; pagination remains consistent
- [x] Cursor stability: no skips/dups with concurrent inserts
- [x] OpenAPI: endpoints documented with filter params; CI validates spec

Current focus
- [x] Implement advanced filters in service/repository and UI chips; persist URL state
- [x] Add Swagger UI scaffolding, expand OpenAPI
- [x] Add latency histograms and Redis op metrics
- [~] RBAC/token middleware scaffolding
