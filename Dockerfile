# Stage 1: Minify embedded JavaScript without modifying tracked source files.
FROM node:24.21.0-alpine3.23@sha256:9ec4a2e289874ed0d722e1772ec2de45d2801541db8612f3638b26f128c69ac2 AS assets

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY scripts/build-assets.cjs ./scripts/build-assets.cjs
COPY cmd/server/static/js ./cmd/server/static/js
RUN npm run build:assets

# Stage 2: Build
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

WORKDIR /app

# Install only the build dependency required for module retrieval.
RUN apk add --no-cache git

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Overlay generated assets before go:embed runs. URLs and load order stay intact.
COPY --from=assets /app/.build/js/ ./cmd/server/static/js/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o blocklist-server ./cmd/server/main.go

# Stage 3: Final Image (no Node.js or npm dependencies)
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
LABEL maintainer="arumes31 <https://github.com/arumes31>"
LABEL org.opencontainers.image.source="https://github.com/arumes31"
LABEL org.opencontainers.image.description="Hardened Blocklist API with GeoIP and RBAC"

# Create a non-root user
RUN addgroup -S blocklist && adduser -S blocklist -G blocklist

# Install runtime data and apply targeted OpenSSL security updates without a
# non-reproducible full-system upgrade.
RUN apk add --no-cache --upgrade ca-certificates tzdata libcrypto3 libssl3

WORKDIR /home/blocklist/

# Copy the binary from builder
COPY --from=builder --chown=blocklist:blocklist /app/blocklist-server .

# Create GeoIP directories and ensure permissions
RUN mkdir -p /usr/share/GeoIP /home/blocklist/geoip && \
    chown -R blocklist:blocklist /home/blocklist/

USER blocklist

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

ENTRYPOINT ["./blocklist-server"]
