# Stage 1: Build
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

WORKDIR /app

# Install only the build dependency required for module retrieval.
RUN apk add --no-cache git

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o blocklist-server ./cmd/server/main.go

# Stage 2: Final Image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
LABEL maintainer="arumes31 <https://github.com/arumes31>"
LABEL org.opencontainers.image.source="https://github.com/arumes31"
LABEL org.opencontainers.image.description="Hardened Blocklist API with GeoIP and RBAC"

# Create a non-root user
RUN addgroup -S blocklist && adduser -S blocklist -G blocklist

# Install runtime trust and timezone data without a non-reproducible full upgrade.
RUN apk add --no-cache ca-certificates tzdata

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
