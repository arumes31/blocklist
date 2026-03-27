package api

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebSocket_CheckOrigin(t *testing.T) {
	tests := []struct {
		name          string
		origin        string
		host          string
		tls           bool
		forwardProto string
		expected      bool
	}{
		{
			name:     "Matching Origin and Host (HTTP)",
			origin:   "http://localhost:5000",
			host:     "localhost:5000",
			expected: true,
		},
		{
			name:     "Mismatching Origin",
			origin:   "http://evil.com",
			host:     "localhost:5000",
			expected: false,
		},
		{
			name:     "No Origin Header",
			origin:   "",
			host:     "localhost:5000",
			expected: true,
		},
		{
			name:     "Mismatching port",
			origin:   "http://localhost:8080",
			host:     "localhost:5000",
			expected: false,
		},
		{
			name:     "Malformed Origin",
			origin:   "://invalid",
			host:     "localhost:5000",
			expected: false,
		},
		{
			name:     "Case-insensitive host match",
			origin:   "http://LocalHost:5000",
			host:     "localhost:5000",
			expected: true,
		},
		{
			name:     "Matching Origin and Host (HTTPS via TLS)",
			origin:   "https://localhost:5000",
			host:     "localhost:5000",
			tls:      true,
			expected: true,
		},
		{
			name:          "Matching Origin and Host (HTTPS via Forwarded-Proto)",
			origin:        "https://localhost:5000",
			host:          "localhost:5000",
			forwardProto: "https",
			expected:      true,
		},
		{
			name:     "Scheme Mismatch (Origin HTTP, Request HTTPS)",
			origin:   "http://localhost:5000",
			host:     "localhost:5000",
			tls:      true,
			expected: false,
		},
		{
			name:     "Scheme Mismatch (Origin HTTPS, Request HTTP)",
			origin:   "https://localhost:5000",
			host:     "localhost:5000",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/ws", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.forwardProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardProto)
			}

			// We access the global upgrader variable from handlers.go
			result := upgrader.CheckOrigin(req)
			assert.Equal(t, tt.expected, result, "CheckOrigin result for origin %s and host %s (tls: %v, proto: %s)", tt.origin, tt.host, tt.tls, tt.forwardProto)
		})
	}
}
