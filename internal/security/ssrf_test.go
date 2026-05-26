package security

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type dummyRawConn struct{}

func (d *dummyRawConn) Control(f func(fd uintptr)) error           { return nil }
func (d *dummyRawConn) Read(f func(fd uintptr) (done bool)) error  { return nil }
func (d *dummyRawConn) Write(f func(fd uintptr) (done bool)) error { return nil }

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
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"224.0.0.1", true}, // Multicast
		{"ff02::1", true},   // IPv6 Multicast
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if tt.ip == "" {
				ip = nil
			}
			assert.Equal(t, tt.expected, IsInternalIP(ip))
		})
	}
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://google.com", true},
		{"http://example.com", true},
		{"http://127.0.0.1", false},
		{"https://10.0.0.1/path", false},
		{"ftp://example.com", false},
		{"invalid-url", false},
		{"http://", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := IsSafeURL(tt.url)
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestSafeSocketControl(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		address  string
		expected bool
	}{
		{"Public IP", "tcp", "8.8.8.8:443", true},
		{"Private IP", "tcp", "10.0.0.1:443", false},
		{"Loopback IP", "tcp", "127.0.0.1:80", false},
		{"IPv6 Loopback", "tcp", "[::1]:80", false},
		{"Hostname instead of IP", "tcp", "example.com:80", false},
		{"Invalid address", "tcp", "not-an-ip", false},
	}

	conn := &dummyRawConn{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SafeSocketControl(tt.network, tt.address, conn)
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
