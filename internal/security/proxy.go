package security

import (
	"net"
	"net/http"
	"net/netip"
)

// ParsePrefixes converts trusted-proxy entries (single IPs or CIDRs) to
// prefixes, skipping entries that do not parse.
func ParsePrefixes(entries []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		if p, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, p)
		} else if a, err := netip.ParseAddr(entry); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return prefixes
}

// IsHTTPS reports whether the client connection is HTTPS. X-Forwarded-Proto
// is honoured only when the direct peer is a trusted proxy; any other client
// could set it to skip redirects or to spoof generated absolute URLs.
func IsHTTPS(r *http.Request, trusted []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") != "https" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	peer = peer.Unmap()
	for _, p := range trusted {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}
