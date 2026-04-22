package security

import (
	"net"
	"net/url"
	"strings"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// IsInternalIP returns true if the given IP is a private or loopback address.
func IsInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Use built-in methods for standard ranges
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	// Fallback for any other explicitly defined blocks
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// IsSafeURL checks if the URL is safe from SSRF by validating the scheme and host.
// It performs DNS resolution to ensure the domain does not resolve to an internal IP.
func IsSafeURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Only allow http and https
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	host := u.Hostname()
	if host == "" {
		return false
	}

	// Check if host is a literal IP
	if ip := net.ParseIP(host); ip != nil {
		return !IsInternalIP(ip)
	}

	// Prevent obvious internal names
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" {
		return false
	}

	// Resolve DNS and check resulting IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we can't resolve it, we might want to be conservative or let it through.
		// For SSRF protection, it's safer to block if resolution fails or is suspicious.
		return false
	}

	for _, ip := range ips {
		if IsInternalIP(ip) {
			return false
		}
	}

	return true
}
