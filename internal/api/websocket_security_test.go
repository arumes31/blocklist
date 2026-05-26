package api

import (
	"blocklist/internal/config"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebSocket_CheckOrigin(t *testing.T) {
	cfg := &config.Config{
		TrustedProxies: "1.1.1.1,2.2.2.0/24",
	}
	h := NewAPIHandler(HandlerOptions{Config: cfg})

	tests := []struct {
		name         string
		origin       string
		host         string
		remoteAddr   string
		tls          bool
		forwardProto string
		expected     bool
	}{
		{
			name:       "Matching Origin and Host (HTTP)",
			origin:     "http://localhost:5000",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   true,
		},
		{
			name:       "Mismatching Origin",
			origin:     "http://evil.com",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   false,
		},
		{
			name:       "No Origin Header",
			origin:     "",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   true,
		},
		{
			name:       "Mismatching port",
			origin:     "http://localhost:8080",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   false,
		},
		{
			name:       "Malformed Origin",
			origin:     "://invalid",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   false,
		},
		{
			name:       "Case-insensitive host match",
			origin:     "http://LocalHost:5000",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   true,
		},
		{
			name:       "Matching Origin and Host (HTTPS via TLS)",
			origin:     "https://localhost:5000",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			tls:        true,
			expected:   true,
		},
		{
			name:         "Matching Origin and Host (HTTPS via Forwarded-Proto from Trusted IP)",
			origin:       "https://localhost:5000",
			host:         "localhost:5000",
			remoteAddr:   "1.1.1.1:1234",
			forwardProto: "https",
			expected:     true,
		},
		{
			name:         "Matching Origin and Host (HTTPS via Forwarded-Proto from Default Trusted Local IP)",
			origin:       "https://localhost:5000",
			host:         "localhost:5000",
			remoteAddr:   "127.0.0.1:1234",
			forwardProto: "https",
			expected:     true,
		},
		{
			name:         "Spoofed Forwarded-Proto from Untrusted IP",
			origin:       "https://localhost:5000",
			host:         "localhost:5000",
			remoteAddr:   "8.8.8.8:1234",
			forwardProto: "https",
			expected:     false,
		},
		{
			name:         "HTTPS via Forwarded-Proto from Trusted Subnet",
			origin:       "https://localhost:5000",
			host:         "localhost:5000",
			remoteAddr:   "2.2.2.50:1234",
			forwardProto: "https",
			expected:     true,
		},
		{
			name:       "Scheme Mismatch (Origin HTTP, Request HTTPS)",
			origin:     "http://localhost:5000",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			tls:        true,
			expected:   false,
		},
		{
			name:       "Scheme Mismatch (Origin HTTPS, Request HTTP)",
			origin:     "https://localhost:5000",
			host:       "localhost:5000",
			remoteAddr: "127.0.0.1:1234",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/ws", nil)
			req.Host = tt.host
			req.RemoteAddr = tt.remoteAddr
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.forwardProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardProto)
			}

			result := h.upgrader.CheckOrigin(req)
			assert.Equal(t, tt.expected, result, "CheckOrigin result for origin %s and host %s (tls: %v, proto: %s, remote: %s)", tt.origin, tt.host, tt.tls, tt.forwardProto, tt.remoteAddr)
		})
	}
}
