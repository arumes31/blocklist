package security

import (
	"net"
	"testing"
)

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		ip       net.IP
		expected bool
	}{
		{net.ParseIP("127.0.0.1"), true},
		{net.ParseIP("10.0.0.1"), true},
		{net.ParseIP("172.16.0.1"), true},
		{net.ParseIP("192.168.1.1"), true},
		{net.ParseIP("169.254.0.1"), true},
		{net.ParseIP("8.8.8.8"), false},
		{net.ParseIP("1.1.1.1"), false},
		{net.ParseIP("0.0.0.0"), true},
		{net.ParseIP("::1"), true},
		{net.ParseIP("fe80::1"), true},
		{net.ParseIP("ff02::1"), true},
		{nil, false},
	}

	for _, tt := range tests {
		if result := IsInternalIP(tt.ip); result != tt.expected {
			t.Errorf("IsInternalIP(%v) = %v, want %v", tt.ip, result, tt.expected)
		}
	}
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://example.com", false},
		{"https://example.com", false},
		{"http://127.0.0.1", true},
		{"https://10.0.0.1", true},
		{"ftp://example.com", true},
		{"http://localhost", true},
		{"invalid-url", true},
		{"", true},
	}

	for _, tt := range tests {
		err := IsSafeURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("IsSafeURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
		}
	}
}

func TestSafeSocketControl(t *testing.T) {
	tests := []struct {
		network string
		address string
		wantErr bool
	}{
		{"tcp", "1.1.1.1:80", false},
		{"tcp", "127.0.0.1:80", true},
		{"tcp", "10.0.0.1:443", true},
		{"tcp", "not-an-ip:80", true},
		{"tcp", "8.8.8.8", false}, // No port, should still work if it's an IP
		{"tcp", "127.0.0.1", true},
	}

	for _, tt := range tests {
		// SafeSocketControl takes a syscall.RawConn which we don't easily have here for unit tests
		// but we can call it with nil if we only want to test the IP check logic before it uses the conn.
		// However, it doesn't use the conn until AFTER the IP check.
		err := SafeSocketControl(tt.network, tt.address, nil)
		if (err != nil) != tt.wantErr {
			t.Errorf("SafeSocketControl(%q, %q) error = %v, wantErr %v", tt.network, tt.address, err, tt.wantErr)
		}
	}
}
