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
		// IPv4 Private
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		// IPv4 Loopback
		{"127.0.0.1", true},
		// IPv4 Link-local
		{"169.254.0.1", true},
		// IPv4 Public
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		// IPv6 Private/Unique Local
		{"fc00::1", true},
		{"fd00::1", true},
		// IPv6 Loopback
		{"::1", true},
		// IPv6 Link-local
		{"fe80::1", true},
		// IPv6 Public
		{"2001:4860:4860::8888", false},
		// Special cases
		{"0.0.0.0", true}, // Unspecified
		{"::", true},      // Unspecified
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			assert.NotNil(t, ip)
			assert.Equal(t, tt.expected, IsInternalIP(ip))
		})
	}

	t.Run("nil IP", func(t *testing.T) {
		assert.False(t, IsInternalIP(nil))
	})
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
		wantErr  string
	}{
		// Valid external URLs
		{"https://www.google.com", true, ""},
		{"http://example.com/path?query=1", true, ""},
		// Invalid schemes
		{"ftp://example.com", false, "unsupported scheme"},
		{"file:///etc/passwd", false, "unsupported scheme"},
		// Internal IP literals (might resolve or be caught by literal check)
		{"http://127.0.0.1", false, "internal IP"},
		{"https://10.0.0.1", false, "internal IP"},
		{"http://[::1]", false, "internal IP"},
		// Invalid host
		{"http://", false, "invalid URL host"},
		// Host resolving to internal IP
		{"http://localhost", false, "internal IP"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := IsSafeURL(tt.url)
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				if tt.wantErr != "" {
					assert.Contains(t, err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestSafeSocketControl(t *testing.T) {
	tests := []struct {
		address  string
		expected bool
	}{
		{"8.8.8.8:53", true},
		{"127.0.0.1:80", false},
		{"10.0.0.1:443", false},
		{"[::1]:80", false},
		{"google.com:80", false}, // SafeSocketControl expects resolved IP
		{"invalid-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			// syscall.RawConn is an interface, we can pass nil as it's not used in the function
			err := SafeSocketControl("tcp", tt.address, nil)
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
