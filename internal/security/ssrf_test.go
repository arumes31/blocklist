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
		{"0.0.0.0", true},   // Unspecified
		{"::", true},        // Unspecified
		{"224.0.0.1", true}, // Link-local multicast
		{"ff02::1", true},   // Link-local multicast
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:4860:4860::8888", false},
		// Additional cases for coverage and robustness
		{"::ffff:127.0.0.1", true}, // IPv4-mapped loopback
		{"::ffff:10.0.0.1", true},  // IPv4-mapped private
		{"::ffff:8.8.8.8", false},  // IPv4-mapped public
		{"fc00::1", true},          // ULA
		{"fe80::1", true},          // Link-local unicast
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
	// IsSafeURL is a best-effort pre-flight check; the authoritative SSRF defense
	// is the socket-level SafeSocketControl hook (see TestSafeSocketControl), which
	// re-validates the actually-dialed IP and cannot be bypassed by DNS rebinding.
	// The "localhost" and "*.invalid" vectors below rely only on RFC-reserved names
	// (RFC 6761 localhost -> loopback; RFC 2606 .invalid -> never resolves), so they
	// are deterministic rather than dependent on ambient DNS.
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://google.com", false},
		{"http://example.com", false},
		{"http://8.8.8.8", false}, // Public IP literal
		{"http://127.0.0.1", true},
		{"http://[::1]", true},
		{"http://10.0.0.1", true},
		{"http://localhost", true},                    // Resolves to 127.0.0.1/::1
		{"http://nonexistent.example.invalid", false}, // DNS fail, but no internal IP found
		{"ftp://example.com", true},
		{"javascript:alert(1)", true},
		{"", true},
		{"http://", true},
		{"http://google.com:80", false},
		{"http://1.1.1.1:443", false},
		{"http://example.com:abc", true}, // url.ParseRequestURI error: invalid port
		{"http://[::1", true},            // url.ParseRequestURI error: missing ']' in address
		{"http://user:pass@host/path?query#fragment", false},
		{"HTTP://EXAMPLE.COM", false}, // Case-insensitive scheme check
		// Additional cases for coverage
		{"http://[::ffff:127.0.0.1]", true},
		{"https://[2001:4860:4860::8888]", false},
		{"https://[fc00::1]", true},
		{"http://127.0.0.1:8080", true}, // IP literal with port
		// Reserved space that Go's IsPrivate/IsLoopback do not cover but that is
		// still reachable inside many hosting environments.
		{"http://100.64.0.1", true},          // RFC 6598 shared address space (CGNAT)
		{"http://0.0.0.1", true},             // RFC 1122 "this network"
		{"http://198.18.0.1", true},          // RFC 2544 benchmarking
		{"http://192.0.0.1", true},           // RFC 6890 protocol assignments
		{"http://255.255.255.255", true},     // limited broadcast
		{"http://224.0.0.1", true},           // multicast
		{"http://[::ffff:100.64.0.1]", true}, // IPv4-mapped CGNAT
		{"http://169.254.169.254", true},     // cloud metadata (link-local)
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
		// Additional cases for coverage
		{"tcp", "8.8.8.8", false},  // Address without port
		{"tcp", "127.0.0.1", true}, // Address without port (internal)
		{"tcp", "[::1]:80", true},  // IPv6 with brackets
		{"tcp", "::1", true},       // IPv6 without brackets
		{"tcp", "::ffff:127.0.0.1", true},
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
