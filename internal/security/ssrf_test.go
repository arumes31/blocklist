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
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"169.254.169.254", true},
		{"::1", true},
		{"fe80::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := IsInternalIP(net.ParseIP(tt.ip)); got != tt.expected {
				t.Errorf("IsInternalIP(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://google.com", false},
		{"https://google.com", false},
		{"http://127.0.0.1", true},
		{"http://10.0.0.1", true},
		{"http://169.254.169.254", true},
		{"ftp://google.com", true},
		{"http://", true},
		// A non-existent domain should currently NOT return an error because LookupIP failure is ignored
		{"http://nonexistent.domain.example.invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := IsSafeURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsSafeURL(%s) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
