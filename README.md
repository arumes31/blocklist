<p align="center">
  <img src="cd/logo.png" alt="Blocklist" width="180" />
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go" alt="Go 1.22+" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Redis-required-DC382D?logo=redis&logoColor=white" alt="Redis required" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Docker-supported-2496ED?logo=docker&logoColor=white" alt="Docker supported" /></a>
  <a href="#"><img src="https://img.shields.io/badge/CI-GitHub_Actions-blue?logo=githubactions" alt="CI" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Coverage-TBD-lightgrey" alt="Coverage" /></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" /></a>
</p>

Blocklist

A consolidated, production-oriented IP blocklist service. It ingests events (firewall, WAF, DoS, application signals), persists them, and exposes curated outputs for enforcement and automation.

High-level flow
- Sources (firewall/WAF/IDS/app) -> blocklist API -> storage (Redis/Postgres) -> outputs (raw, JSON, automate) -> consumers (firewall/WAF/jobs)

Project structure
- cmd/server: Go web server (HTTP API, templates, static assets)
- internal/api: HTTP handlers, websockets hub
- internal/config: configuration and validation
- internal/models: domain models
- internal/repository: Redis/Postgres access layers
- internal/service: business logic (auth, IP, GeoIP, scheduler)
- server/static, server/templates: static files and HTML templates
- Dockerfile.go, docker-compose.go.yml: containerization for Go stack

Key capabilities
- Dashboard for viewing and managing blocked IPs and whitelist (admin-only)
- Webhook endpoints to add/remove IPs (authenticated)
- Rate limiting per endpoint and per IP
- GeoIP enrichment when database available
- Background tasks for expiration and cached views
- Raw feeds for simple consumers (/raw, /ips, /ips_automate)

Requirements
- Go 1.22+
- Redis (for fast storage, rate limiting, and caches)
- Optional: Postgres (if repository is configured to use it)
- Optional: MaxMind GeoLite2 databases (City/Country/ASN) on a shared volume

Quick start (development)
1) Clone repository and enter project directory.
2) Set required environment variables (see Configuration). Minimal example:
   - REDIS_HOST=localhost
   - REDIS_PORT=6379
   - SECRET_KEY=<random-32-bytes>
   - GUIAdmin=admin
   - GUIPassword=<strong-password>
   - GUIToken=<base32 TOTP seed>
   - BLOCKED_RANGES="127.0.0.1/32,0.0.0.0/32,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
   - WEBHOOK2_ALLOWED_IPS="127.0.0.1"
3) Start Redis locally.
4) Build and run the Go server:
   - go build -o bin/blocklist ./cmd/server
   - ./bin/blocklist
5) Open http://localhost:5000 and log in.

Docker (Go stack)
- Build: docker build -f Dockerfile.go -t blocklist:go .
- Run with compose: docker compose -f docker-compose.go.yml up -d

HTTP endpoints (server)
- GET /login, POST /login, POST /login/totp: two-step admin auth (password + TOTP)
- GET /dashboard: dashboard UI (admin-only)
- POST /block: add an IP to blocklist (admin-only)
- POST /unblock: remove an IP (admin-only)
- GET /whitelist: view whitelist (admin-only)
- POST /add_whitelist: add IP/subnet to whitelist (admin-only)
- POST /remove_whitelist: remove IP/subnet from whitelist (admin-only)
- GET /ips: JSON array of blocked IPs
- GET /raw: newline-delimited list of blocked IPs
- GET /ips_automate: filtered/cached list optimized for automation
- Static assets: /js/*, /cd/*

Authentication and authorization
- Admin login requires password and TOTP. Sessions are IP-bound and expire after inactivity.
- Webhook endpoints require basic credentials provided via JSON payload or configured headers (see configuration). Only trusted sources should reach these paths.

Rate limiting
- Global and route-level limits enforced per client IP.
- Bypass for trusted internal health checks can be configured.

GeoIP
- If GEOIP databases are mounted at /usr/share/GeoIP (container) or configured path, the service enriches entries with country/city. Absence of DB gracefully degrades to no geo data.

Expiration and caches
- Entries typically expire after 24 hours unless marked persistent. Background tasks refresh cached responses for /ips_automate to keep responses fast and predictable.

Configuration
Environment variables (common):
- SECRET_KEY: session/cookie encryption secret (required)
- GUIAdmin: primary admin username (required)
- GUIPassword: primary admin password (required)
- GUIToken: base32 TOTP seed for the primary admin (required)
- BLOCKED_RANGES: comma-separated CIDR list that cannot be added via webhook (e.g., private ranges)
- WEBHOOK2_ALLOWED_IPS: comma-separated list of IPs allowed to access certain raw endpoints
- REDIS_HOST, REDIS_PORT, REDIS_DB: Redis configuration
- REDIS_LIM_DB: Redis DB index for rate limiter state
- LOGWEB: set to "true" to increase log verbosity
- GEOIP paths or mounting instructions if using Docker

Security best practices
- Do not commit secrets. Use environment variables, secret managers, or mounted files.
- Restrict admin endpoints via firewall/WAF and VPN where possible.
- Trust proxy headers (X-Forwarded-For) only when running behind known reverse proxies.
- Never expose TOTP secrets or QR URIs to non-admin users; avoid logging secrets.

Migration from legacy Python/Flask
- The legacy Flask app and Dockerfiles have been removed. The Go server implements equivalent features: admin auth with TOTP, rate limiting, geo enrichment, whitelist, and automation endpoints. Validate parity in your environment and migrate any external integrations to the new endpoints documented above.

Testing
- Unit tests for services live under internal/service (e.g., ip_service_test.go). Run: go test ./...

License
- MIT (or project-specific license). Update this section as applicable.

Links
- Raw feed example: https://blocklist.eworx.at/raw
