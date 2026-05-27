package security

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// IsInternalIP returns true if the IP belongs to a private network, loopback,
// unspecified, link-local, or multicast address space.
func IsInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast()
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

	// Try resolving the host.
	// If it fails to resolve, we allow it through here and let downstream socket-level
	// protection (SafeSocketControl) handle it during the actual dial.
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
