package security

import (
	"net"
	"syscall"
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
		{"192.168.0.1", true},
		{"169.254.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			assert.Equal(t, tt.expected, IsInternalIP(ip))
		})
	}

	assert.False(t, IsInternalIP(nil))
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"Valid HTTP", "http://example.com", false},
		{"Valid HTTPS", "https://example.com", false},
		{"Invalid Scheme", "ftp://example.com", true},
		{"Internal IP literal", "http://127.0.0.1", true},
		{"Internal IP literal private", "http://10.0.0.1", true},
		{"Malformed URL", "http://[::1", true},
		{"No Host", "http://", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsSafeURL(tt.rawURL)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSafeSocketControl(t *testing.T) {
	// Mocking syscall.RawConn is complex, but SafeSocketControl doesn't use it.
	// It only uses the network and address arguments.
	var dummyConn syscall.RawConn

	tests := []struct {
		name    string
		network string
		address string
		wantErr bool
	}{
		{"Public IP", "tcp", "8.8.8.8:443", false},
		{"Internal IP", "tcp", "127.0.0.1:80", true},
		{"Private IP", "tcp", "10.0.0.1:80", true},
		{"Invalid IP", "tcp", "not-an-ip:80", true},
		{"Public IP no port", "tcp", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SafeSocketControl(tt.network, tt.address, dummyConn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
