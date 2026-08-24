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

// nonPublicRanges covers special-purpose blocks that Go's IP classifiers do
// not consistently identify as private. Outbound user-controlled requests have
// no valid reason to target documentation, benchmarking, transition, discard,
// or future-use address space, and some of these ranges are routed internally.
var nonPublicRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 1122 "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 shared address space
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved and limited broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // well-known NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // deprecated 6to4
}

// IsInternalIP reports whether the IP belongs to private, loopback,
// unspecified, link-local, multicast, or otherwise reserved address space.
func IsInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
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
	for _, r := range nonPublicRanges {
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
	if u.User != nil {
		return errors.New("URL credentials are not allowed")
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("invalid URL host")
	}

	// Try resolving the host
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve URL host: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("URL host did not resolve to an IP address")
	}
	for _, ip := range ips {
		if IsInternalIP(ip) {
			return fmt.Errorf("URL resolves to non-public IP: %s", ip.String())
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
