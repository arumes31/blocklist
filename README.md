<p align="center">
  <img src="cd/logo.png" alt="Blocklist" width="180" />
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Go-1.25.6-00ADD8?logo=go" alt="Go 1.25.6" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Redis-required-DC382D?logo=redis&logoColor=white" alt="Redis required" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Docker-hardened-2496ED?logo=docker&logoColor=white" alt="Docker hardened" /></a>
  <a href="#"><img src="https://img.shields.io/badge/CI-GitHub_Actions-blue?logo=githubactions" alt="CI" /></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" /></a>
</p>

# Blocklist App (Go Edition)

A high-performance, security-hardened IP management platform with GeoIP enrichment, real-time updates via WebSockets, and advanced filtering capabilities.

## Key Features

- **Advanced Filtering**: Server-side filtering by IP, Reason, Country, Added By, and Date Range (ISO8601).
- **Real-time Updates**: Live dashboard updates via WebSockets with pause/resume controls.
- **RBAC & Security**: Role-Based Access Control (Viewer, Operator, Admin) and API Token authentication.
- **GeoIP Enrichment**: Automated country and city detection for blocked/whitelisted IPs.
- **Observability**: Prometheus metrics for HTTP latency, Redis operation timing, and block/unblock counters.
- **Hardened Deployment**: Non-root Docker images based on Alpine 3.21 with integrated health checks.

## Project Structure
- `cmd/server`: Go web server entry point, migrations, and static/template assets.
- `internal/api`: HTTP handlers, middlewares, and WebSocket hub.
- `internal/metrics`: Prometheus metrics definitions.
- `internal/repository`: Redis and PostgreSQL data access layers.
- `internal/service`: Core business logic (Auth, IP management, GeoIP, Scheduling).

## API Endpoints

### Automated Webhooks
- **`POST /webhook`**: Legacy/Compatibility endpoint for ban/unban actions.
- **`POST /api/v1/webhook`**: Hardened version of the webhook (requires Auth).
    - **Body**: `{"ip": "1.2.3.4", "act": "ban", "username": "...", "password": "..."}`
- **`POST /api/v1/webhook2_whitelist`**: Automatically whitelists the caller's IP.

### Data & Stats
- **`GET /api/v1/ips`**: Paginated list of blocked IPs with advanced filters.
    - **Query Params**: `limit`, `cursor`, `query`, `country`, `added_by`, `from`, `to`.
- **`GET /api/v1/stats`**: Aggregate statistics (hour, day, total, top countries).
- **`GET /api/v1/raw`**: Plain-text list of blocked IPs for firewall ingestion.

### Documentation & Health
- **`GET /openapi.json`**: Full OpenAPI 3.0.1 specification.
- **`GET /health`**: Simple health check (Postgres + Redis connectivity).
- **`GET /ready`**: Readiness check with dependency details.
- **`GET /metrics`**: Prometheus-formatted metrics.

## RBAC Roles

| Role | Permissions |
| :--- | :--- |
| **Viewer** | View dashboard, search IPs, view stats. |
| **Operator** | All Viewer permissions + Block/Unblock IPs, manage Whitelist. |
| **Admin** | All Operator permissions + Manage Admin accounts and API tokens. |

## Quick Start (Development)

1. **Configure Environment**: Set required variables in `.env` (see Configuration).
2. **Start Dependencies**: Ensure Redis and PostgreSQL are running.
3. **Run Migrations**: Handled automatically on server start.
4. **Build & Run**:
   ```bash
   go build -o blocklist-server ./cmd/server/main.go
   ./blocklist-server
   ```

## Docker Deployment
- **Build**: `docker build -t blocklist:go .`
- **Run**: `docker compose -f docker-compose.go.yml up -d`

## Configuration
- `SECRET_KEY`: Session encryption secret (required).
- `GUIAdmin`/`GUIPassword`: Primary admin credentials.
- `DATABASE_URL`: PostgreSQL connection string.
- `REDIS_HOST`/`REDIS_PORT`: Redis configuration.
- `BLOCKED_RANGES`: CIDR list that cannot be added via webhook.

## Testing
```bash
go test ./...
```

## License
MIT