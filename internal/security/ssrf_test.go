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
		{"::1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.0.1", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:4860:4860::8888", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}
			assert.Equal(t, tt.expected, IsInternalIP(ip))
		})
	}
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"Valid HTTPS", "https://google.com", false},
		{"Valid HTTP", "http://example.com", false},
		{"Internal IP literal", "http://127.0.0.1", true},
		{"Internal IP literal 10.x", "http://10.0.0.1", true},
		{"Private IP literal 192.x", "http://192.168.1.1", true},
		{"Unsupported scheme ftp", "ftp://example.com", true},
		{"Unsupported scheme file", "file:///etc/passwd", true},
		{"Localhost", "http://localhost", true},
		{"Invalid URL", "http://[::1", true},
		{"Empty host", "http://", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsSafeURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSafeSocketControl(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"Internal IP 127.0.0.1", "127.0.0.1:80", true},
		{"Internal IP 10.0.0.1", "10.0.0.1:443", true},
		{"Public IP 8.8.8.8", "8.8.8.8:53", false},
		{"Public IPv6", "2001:4860:4860::8888:443", false},
		{"Invalid IP", "not-an-ip:80", true},
		{"Internal IP no port", "127.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// c is nil because SafeSocketControl doesn't use it yet
			err := SafeSocketControl("tcp", tt.address, nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
