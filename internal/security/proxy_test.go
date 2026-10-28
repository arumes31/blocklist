package security

import (
	"crypto/tls"
	"net"
	"net/http/httptest"
	"testing"
)

func TestIsHTTPSHonoursForwardedProtoOnlyFromTrustedProxies(t *testing.T) {
	trusted := ParsePrefixes([]string{"127.0.0.1/32", "10.0.0.5"})
	for _, tc := range []struct {
		name, remote, proto string
		tls                 bool
		want                bool
	}{
		{name: "direct TLS", remote: "198.51.100.1:443", tls: true, want: true},
		{name: "trusted proxy https", remote: "10.0.0.5:1234", proto: "https", want: true},
		{name: "trusted proxy http", remote: "10.0.0.5:1234", proto: "http"},
		{name: "untrusted client spoofs https", remote: "198.51.100.1:1234", proto: "https"},
		{name: "plain http", remote: "127.0.0.1:1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			if tc.proto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := IsHTTPS(r, trusted); got != tc.want {
				t.Fatalf("IsHTTPS = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsInternalIPCoversDeprecatedIPv6Ranges(t *testing.T) {
	for _, ip := range []string{"::7f00:1", "fec0::1"} {
		if !IsInternalIP(net.ParseIP(ip)) {
			t.Fatalf("%s must be treated as internal", ip)
		}
	}
}
