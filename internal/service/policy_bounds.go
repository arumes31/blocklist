package service

import (
	"errors"
	"net/netip"
	"strings"
)

// Allowlist and exclusion entries suppress blocking for every address they
// cover, so their breadth is bounded. Any caller is held to the absolute
// minimum; create-only callers (whitelist_ips, exclude_ips) are held to the
// narrower bound so they cannot add an entry broad enough to switch off
// blocking for large parts of the address space. Broader entries need
// manage_whitelist or manage_excluded.
const (
	MinPolicyPrefixV4           = 8
	MinPolicyPrefixV6           = 16
	MinCreateOnlyPolicyPrefixV4 = 16
	MinCreateOnlyPolicyPrefixV6 = 32
)

// ErrPolicyPrefixTooBroad reports an allowlist or exclusion prefix that covers
// more addresses than the caller may exempt.
var ErrPolicyPrefixTooBroad = errors.New("prefix is too broad")

var ipv4MappedRange = netip.MustParsePrefix("::ffff:0:0/96")

// ErrInvalidPolicyReason reports a reason that cannot be recorded in the audit
// log (invalid UTF-8 or a NUL character).
var ErrInvalidPolicyReason = errors.New("reason contains characters that cannot be recorded")

// ValidAuditText reports whether text can be stored in the audit log.
func ValidAuditText(text string) bool { return validAuditText(text) }

// CheckPolicyBreadth returns ErrPolicyPrefixTooBroad when value is a CIDR
// prefix shorter than the minimum for the caller. Single addresses, FQDNs and
// wildcards are not prefixes and always pass.
func CheckPolicyBreadth(value string, createOnly bool) error {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		return nil
	}
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	p = canonicalPrefix(p)
	minV4, minV6 := MinPolicyPrefixV4, MinPolicyPrefixV6
	if createOnly {
		minV4, minV6 = MinCreateOnlyPolicyPrefixV4, MinCreateOnlyPolicyPrefixV6
	}
	minBits := minV6
	if p.Addr().Is4() {
		minBits = minV4
	}
	if p.Bits() < minBits {
		return ErrPolicyPrefixTooBroad
	}
	// An IPv6 prefix shorter than /96 that overlaps the IPv4-mapped range also
	// matches every IPv4 address (prefixContains compares both spellings), so
	// it is as broad as 0.0.0.0/0.
	if p.Addr().Is6() && p.Bits() < 96 && p.Overlaps(ipv4MappedRange) {
		return ErrPolicyPrefixTooBroad
	}
	return nil
}

// checkPolicyInput applies the breadth and audit-text rules shared by every
// allowlist and exclusion write.
func checkPolicyInput(value, reason string, createOnly bool) error {
	if err := CheckPolicyBreadth(value, createOnly); err != nil {
		return err
	}
	if !validAuditText(reason) {
		return ErrInvalidPolicyReason
	}
	return nil
}
