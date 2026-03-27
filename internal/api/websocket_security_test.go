package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebSocket_CheckOrigin(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		host     string
		expected bool
	}{
		{
			name:     "Matching Origin and Host",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/ws", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			// We access the global upgrader variable from handlers.go
			result := upgrader.CheckOrigin(req)
			assert.Equal(t, tt.expected, result, "CheckOrigin result for origin %s and host %s", tt.origin, tt.host)
		})
	}
}
