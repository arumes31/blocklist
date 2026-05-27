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
		{"::1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"169.254.0.1", true},
		{"fe80::1", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			assert.NotNil(t, ip)
			assert.Equal(t, tt.expected, IsInternalIP(ip))
		})
	}

	t.Run("nil", func(t *testing.T) {
		assert.False(t, IsInternalIP(nil))
	})
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"Valid HTTP", "http://example.com", false},
		{"Valid HTTPS", "https://example.com", false},
		{"Invalid Scheme FTP", "ftp://example.com", true},
		{"Invalid Scheme File", "file:///etc/passwd", true},
		{"Internal IPv4", "http://127.0.0.1", true},
		{"Internal IPv4 Private", "http://10.0.0.1", true},
		{"Internal IPv6", "http://[::1]", true},
		{"Localhost", "http://localhost", true},
		{"Malformed URL", "http://[::1", true},
		{"Empty Host", "http://", true},
		{"No Scheme", "example.com", true},
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

type mockRawConn struct {
	syscall.RawConn
}

func (m *mockRawConn) Control(f func(fd uintptr)) error {
	return nil
}

func TestSafeSocketControl(t *testing.T) {
	mockConn := &mockRawConn{}

	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"Public IP with port", "8.8.8.8:443", false},
		{"Public IP without port", "1.1.1.1", false},
		{"Internal IP with port", "127.0.0.1:80", true},
		{"Internal IP without port", "10.0.0.1", true},
		{"Internal IPv6", "[::1]:443", true},
		{"Invalid IP", "not-an-ip:80", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SafeSocketControl("tcp", tt.address, mockConn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
