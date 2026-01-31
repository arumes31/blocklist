<p align="center">
  <img src="cd/logo.png" alt="Blocklist" width="500" />
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?logo=go" alt="Go 1.24" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Redis-required-DC382D?logo=redis&logoColor=white" alt="Redis required" /></a>
  <a href="#"><img src="https://img.shields.io/badge/Docker-hardened-2496ED?logo=docker&logoColor=white" alt="Docker hardened" /></a>
  <a href="#"><img src="https://img.shields.io/badge/CI-GitHub_Actions-blue?logo=githubactions" alt="CI" /></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" /></a>
</p>

# Blocklist App (Go Edition)

A high-performance, security-hardened IP management platform with GeoIP enrichment, real-time updates via WebSockets, and advanced filtering capabilities.

## 🔄 Project Flow

<p align="center">
  <svg width="600" height="150" viewBox="0 0 600 150" xmlns="http://www.w3.org/2000/svg">
    <rect x="10" y="40" width="100" height="60" rx="10" fill="#8b0000" stroke="#ff0000" stroke-width="2">
      <animate attributeName="opacity" values="0.7;1;0.7" dur="3s" repeatCount="indefinite" />
    </rect>
    <text x="60" y="75" font-family="Arial" font-size="14" fill="white" text-anchor="middle">Sources</text>
    
    <path d="M 115 70 L 165 70" stroke="#ff0000" stroke-width="2" marker-end="url(#arrow)" />
    
    <rect x="175" y="40" width="120" height="60" rx="10" fill="#333" stroke="#ff0000" stroke-width="2" />
    <text x="235" y="75" font-family="Arial" font-size="14" fill="white" text-anchor="middle">Blocklist API</text>
    
    <path d="M 300 70 L 350 70" stroke="#ff0000" stroke-width="2" marker-end="url(#arrow)" />
    
    <rect x="360" y="40" width="100" height="60" rx="10" fill="#333" stroke="#ff0000" stroke-width="2" />
    <text x="410" y="75" font-family="Arial" font-size="14" fill="white" text-anchor="middle">Storage</text>
    
    <path d="M 465 70 L 515 70" stroke="#ff0000" stroke-width="2" marker-end="url(#arrow)" />
    
    <rect x="525" y="40" width="65" height="60" rx="10" fill="#28a745" stroke="#fff" stroke-width="2">
      <animate attributeName="stroke" values="#fff;#28a745;#fff" dur="2s" repeatCount="indefinite" />
    </rect>
    <text x="557" y="75" font-family="Arial" font-size="12" fill="white" text-anchor="middle">Firewall</text>
    
    <defs>
      <marker id="arrow" markerWidth="10" markerHeight="10" refX="0" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L0,6 L9,3 z" fill="#ff0000" />
      </marker>
    </defs>
  </svg>
</p>

## Key Features

- **Advanced Filtering**: Server-side filtering by IP, Reason, Country, Added By, and Date Range (ISO8601).
- **Real-time Updates**: Live dashboard updates via WebSockets with PING/PONG keep-alive.
- **RBAC & Security**: Role-Based Access Control (Viewer, Operator, Admin) and API Token authentication.
- **GeoIP Enrichment**: Automated ASN, Country, and City detection for all entries.
- **Observability**: Prometheus metrics for latency and operations, protected by IP-based ACL.
- **Hardened Deployment**: Non-root Docker images based on Alpine 3.21 with conditional `:latest` tagging.

## Project Structure
- `cmd/server`: Go web server entry point, migrations, and static/template assets.
- `internal/api`: HTTP handlers, middlewares (Auth, RBAC, Metrics), and WebSocket hub.
- `internal/metrics`: Prometheus metrics definitions.
- `internal/repository`: Redis and PostgreSQL data access layers.
- `internal/service`: Core business logic (Auth, IP management, GeoIP, Webhooks).

## API Endpoints

### Automated Webhooks
- **`POST /webhook`**: Legacy endpoint for ban/unban actions.
    - **Example**: `curl -X POST -H "Content-Type: application/json" -d '{"ip":"1.2.3.4","act":"ban","reason":"manual","username":"admin","password":"password"}' http://localhost:5000/webhook`
- **`POST /api/v1/webhook`**: Authenticated webhook (HMAC supported).
    - **Example**: `curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -H "Content-Type: application/json" -d '{"ip":"1.2.3.4","act":"ban","reason":"manual"}' http://localhost:5000/api/v1/webhook`
- **`POST /api/v1/webhook2_whitelist`**: Automatically whitelists the caller's IP.

### Data & Stats
- **`GET /api/v1/ips`**: Paginated list of blocked IPs with advanced filters.
- **`GET /api/v1/ips/export`**: Export data in CSV or NDJSON format.
- **`GET /api/v1/stats`**: Aggregate statistics including top countries, ASNs, and reasons.

## RBAC Roles

| Role | Permissions |
| :--- | :--- |
| **Viewer** | View dashboard, search IPs, view stats, export data. |
| **Operator** | All Viewer permissions + Block/Unblock IPs, manage Whitelist. |
| **Admin** | All Operator permissions + Manage Admin accounts and API tokens. |

## Quick Start (Development)

1. **Configure Environment**: Set required variables in `.env`.
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
- `METRICS_ALLOWED_IPS`: Comma-separated list of trusted IPs for `/metrics`.
- `ENABLE_OUTBOUND_WEBHOOKS`: Set to `true` to enable outbound notifications (default: `false`).
- `WEBHOOK_SECRET`: HMAC secret for signing outbound webhook payloads.

## Testing
Comprehensive unit and integration tests using `miniredis` and `testcontainers-go`.
```bash
go test ./...
```

## GitHub Repository About (Suggested)
**Description:**
Hardened Go-based IP Blocklist manager with GeoIP (ASN/Country), real-time WebSocket dashboard, RBAC, and automated webhooks.

**Topics:**
`golang` `security` `blocklist` `firewall-automation` `geoip` `prometheus` `websockets` `rbac` `docker-hardened`

## License
MIT
