package security

import (
	"net"
	"testing"
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
		{"169.254.0.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IsInternalIP(ip); got != tt.expected {
			t.Errorf("IsInternalIP(%s) = %v, want %v", tt.ip, got, tt.expected)
		}
	}

	if IsInternalIP(nil) != false {
		t.Error("IsInternalIP(nil) should be false")
	}
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://google.com", false},
		{"http://example.com", false},
		{"http://127.0.0.1", true},
		{"http://[::1]", true},
		{"http://10.0.0.1", true},
		{"ftp://example.com", true},
		{"javascript:alert(1)", true},
		{"", true},
		{"http://", true},
	}

	for _, tt := range tests {
		err := IsSafeURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("IsSafeURL(%s) error = %v, wantErr %v", tt.url, err, tt.wantErr)
		}
	}
}

func TestSafeSocketControl(t *testing.T) {
	// Mock RawConn for SafeSocketControl
	mockConn := &mockRawConn{}

	tests := []struct {
		network string
		address string
		wantErr bool
	}{
		{"tcp", "8.8.8.8:80", false},
		{"tcp", "127.0.0.1:80", true},
		{"tcp", "10.0.0.1:443", true},
		{"tcp", "invalid-ip", true},
	}

	for _, tt := range tests {
		err := SafeSocketControl(tt.network, tt.address, mockConn)
		if (err != nil) != tt.wantErr {
			t.Errorf("SafeSocketControl(%s, %s) error = %v, wantErr %v", tt.network, tt.address, err, tt.wantErr)
		}
	}
}

type mockRawConn struct{}

func (m *mockRawConn) Control(f func(fd uintptr)) error {
	return nil
}

func (m *mockRawConn) Read(f func(fd uintptr) (done bool)) error {
	return nil
}

func (m *mockRawConn) Write(f func(fd uintptr) (done bool)) error {
	return nil
}
