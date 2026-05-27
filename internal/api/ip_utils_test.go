package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsIPInCIDRs(t *testing.T) {
	h, _, _, _, _ := setupTest()

	tests := []struct {
		name     string
		ipStr    string
		cidrs    string
		expected bool
	}{
		{
			name:     "Empty CIDRs",
			ipStr:    "1.2.3.4",
			cidrs:    "",
			expected: true,
		},
		{
			name:     "Invalid IP",
			ipStr:    "invalid",
			cidrs:    "1.2.3.0/24",
			expected: false,
		},
		{
			name:     "IP in CIDR",
			ipStr:    "1.2.3.4",
			cidrs:    "1.2.3.0/24",
			expected: true,
		},
		{
			name:     "IP outside CIDR",
			ipStr:    "1.2.4.1",
			cidrs:    "1.2.3.0/24",
			expected: false,
		},
		{
			name:     "Exact IP match",
			ipStr:    "1.2.3.4",
			cidrs:    "1.2.3.4",
			expected: true,
		},
		{
			name:     "Multiple CIDRs, matches one",
			ipStr:    "1.2.3.4",
			cidrs:    "1.1.1.1, 1.2.3.0/24",
			expected: true,
		},
		{
			name:     "Multiple CIDRs with spaces",
			ipStr:    "1.2.3.4",
			cidrs:    " 1.1.1.1 , 1.2.3.0/24 ",
			expected: true,
		},
		{
			name:     "One invalid, one valid matching",
			ipStr:    "1.2.3.4",
			cidrs:    "invalid-cidr, 1.2.3.0/24",
			expected: true,
		},
		{
			name:     "Multiple IPs, no match",
			ipStr:    "1.2.3.4",
			cidrs:    "1.2.3.5, 1.2.3.6",
			expected: false,
		},
		{
			name:     "IPv6 in CIDR",
			ipStr:    "2001:db8::1",
			cidrs:    "2001:db8::/32",
			expected: true,
		},
		{
			name:     "IPv6 outside CIDR",
			ipStr:    "2001:db9::1",
			cidrs:    "2001:db8::/32",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.isIPInCIDRs(tt.ipStr, tt.cidrs)
			assert.Equal(t, tt.expected, result)
		})
	}
}
