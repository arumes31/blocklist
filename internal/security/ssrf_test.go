package security

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			assert.Equal(t, tt.expected, IsInternalIP(ip))
		})
	}
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://google.com/", true},
		{"http://api.external.com/v1", true},
		{"http://127.0.0.1/admin", false},
		{"https://10.0.0.1/callback", false},
		{"http://localhost/status", false},
		{"ftp://example.com", false},
		{"javascript:alert(1)", false},
		{"http://[::1]/", false},
		{"", false},
		{"not-a-url", false},
		// DNS resolution test cases (assuming these resolve as expected in the environment)
		{"http://localtest.me", false}, // Resolves to 127.0.0.1
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsSafeURL(tt.url))
		})
	}
}
