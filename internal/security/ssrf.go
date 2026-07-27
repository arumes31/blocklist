package security

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// reservedRanges are blocks that Go's own IP classifiers do not report as
// private but that must still be unreachable from a user-supplied URL. Shared
// address space in particular is routable inside many hosting environments.
var reservedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // RFC 1122 "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // RFC 6598 shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),       // RFC 6890 IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),      // RFC 2544 benchmarking
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
}

// IsInternalIP reports whether the IP belongs to private, loopback,
// unspecified, link-local, multicast, or otherwise reserved address space.
func IsInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		// An address we cannot classify is not one we should dial.
		return true
	}
	// Unmap so IPv4-mapped IPv6 forms (::ffff:100.64.0.1) match the IPv4 blocks.
	addr = addr.Unmap()
	for _, r := range reservedRanges {
		if r.Contains(addr) {
			return true
		}
	}

	return false
}

// IsSafeURL validates the URL to prevent SSRF at input time.
// It parses the URL, enforces http/https schemes, and checks if the hostname
// directly resolves to an internal IP (basic pre-flight check).
func IsSafeURL(rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return err
	}

	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return errors.New("unsupported scheme, only http and https are allowed")
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("invalid URL host")
	}

	// Try resolving the host
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if IsInternalIP(ip) {
				return fmt.Errorf("URL resolves to internal IP: %s", ip.String())
			}
		}
	}

	// If the host was passed as an IP literal (e.g., http://127.0.0.1/)
	if ip := net.ParseIP(host); ip != nil {
		if IsInternalIP(ip) {
			return fmt.Errorf("URL contains internal IP: %s", ip.String())
		}
	}

	return nil
}

// SafeSocketControl is a syscall.RawConn control function that can be used with net.Dialer
// to protect against DNS rebinding and connecting to internal IPs at dial time.
func SafeSocketControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// If there's no port, address is the host
		host = address
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// During net.Dial, the address string usually contains the resolved IP address,
		// not the hostname. If it's somehow not an IP, we must deny it.
		return fmt.Errorf("SafeSocketControl: failed to parse IP from address %s", address)
	}

	if IsInternalIP(ip) {
		return fmt.Errorf("blocked attempt to connect to internal IP: %s", ip.String())
	}

	return nil
}
