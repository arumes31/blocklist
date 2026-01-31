# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies and patch OS
RUN apk update && apk upgrade --no-cache && apk add --no-cache git

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o blocklist-server ./cmd/server/main.go

# Stage 2: Final Image
FROM alpine:3.21.2
LABEL maintainer="arumes31 <https://github.com/arumes31>"
LABEL org.opencontainers.image.source="https://github.com/arumes31"
LABEL org.opencontainers.image.description="Hardened Blocklist API with GeoIP and RBAC"

# Create a non-root user
RUN addgroup -S blocklist && adduser -S blocklist -G blocklist

# Patch OS and install core utilities
RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata

WORKDIR /home/blocklist/

# Copy the binary from builder
COPY --from=builder --chown=blocklist:blocklist /app/blocklist-server .

# Create GeoIP directory and ensure permissions
RUN mkdir -p /usr/share/GeoIP && chown blocklist:blocklist /usr/share/GeoIP

USER blocklist

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

ENTRYPOINT ["./blocklist-server"]
