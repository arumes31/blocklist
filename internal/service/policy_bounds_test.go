package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPolicyBreadth(t *testing.T) {
	for _, tc := range []struct {
		value      string
		createOnly bool
		ok         bool
	}{
		{"192.0.2.1", true, true},
		{"2001:db8::1", true, true},
		{"example.com", true, true},
		{"*.example.com", true, true},
		{"0.0.0.0/0", false, false},
		{"::/0", false, false},
		{"::ffff:0:0/96", false, false}, // canonicalizes to 0.0.0.0/0
		{"::ffff:0:0/95", false, false}, // also matches every IPv4 address
		{"10.0.0.0/7", false, false},
		{"10.0.0.0/8", false, true},
		{"10.0.0.0/8", true, false},
		{"10.0.0.0/15", true, false},
		{"10.0.0.0/16", true, true},
		{"2001::/15", false, false},
		{"2001::/16", false, true},
		{"2001::/16", true, false},
		{"2001:db8::/32", true, true},
	} {
		err := CheckPolicyBreadth(tc.value, tc.createOnly)
		if tc.ok {
			assert.NoError(t, err, "%s createOnly=%v", tc.value, tc.createOnly)
		} else {
			assert.ErrorIs(t, err, ErrPolicyPrefixTooBroad, "%s createOnly=%v", tc.value, tc.createOnly)
		}
	}
}

// A create-only caller must not be able to whitelist or exclude the whole
// address space, and no caller may store a zero-length prefix.
func TestIPService_PolicyWritesRejectBroadPrefixes(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuditTestService(t, nil)
	ctx := context.Background()

	for _, prefix := range []string{"::/0", "0.0.0.0/0"} {
		created, err := svc.WhitelistIPIfAbsent(ctx, prefix, "maintenance", "moderator", "")
		require.ErrorIs(t, err, ErrPolicyPrefixTooBroad)
		require.False(t, created)
		require.ErrorIs(t, svc.WhitelistIP(ctx, prefix, "maintenance", "admin", ""), ErrPolicyPrefixTooBroad)
		created, err = svc.AddExcludedIfAbsent(ctx, prefix, "maintenance", "moderator", "", false)
		require.ErrorIs(t, err, ErrPolicyPrefixTooBroad)
		require.False(t, created)
		require.ErrorIs(t, svc.AddExcluded(ctx, prefix, "maintenance", "admin", "", false), ErrPolicyPrefixTooBroad)
		_, err = svc.AddSystemExcluded(ctx, prefix, "feed", "")
		require.ErrorIs(t, err, ErrPolicyPrefixTooBroad)
	}

	_, err := svc.WhitelistIPIfAbsent(ctx, "10.0.0.0/8", "too broad for create-only", "moderator", "")
	require.ErrorIs(t, err, ErrPolicyPrefixTooBroad)
	require.NoError(t, svc.WhitelistIP(ctx, "10.0.0.0/8", "operator", "admin", ""))

	list, err := repo.GetWhitelistedIPs()
	require.NoError(t, err)
	require.NotContains(t, list, "::/0")
	require.NotContains(t, list, "0.0.0.0/0")
	require.Contains(t, list, "10.0.0.0/8")

	_, err = svc.BlockIP(ctx, "192.0.2.10", "still blockable", "admin", "", false, time.Hour)
	require.NoError(t, err)
}

// A reason the audit log cannot store must stop the policy change before it
// is written, so no allowlist or exclusion entry exists without its event.
func TestIPService_PolicyWritesRejectUnrecordableReasons(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuditTestService(t, nil)
	ctx := context.Background()

	for _, reason := range []string{"bad\x00reason", "bad\xffreason"} {
		require.ErrorIs(t, svc.WhitelistIP(ctx, "192.0.2.20", reason, "admin", ""), ErrInvalidPolicyReason)
		_, err := svc.WhitelistIPIfAbsent(ctx, "192.0.2.21", reason, "moderator", "")
		require.ErrorIs(t, err, ErrInvalidPolicyReason)
		require.ErrorIs(t, svc.AddExcluded(ctx, "192.0.2.22", reason, "admin", "", false), ErrInvalidPolicyReason)
		_, err = svc.AddExcludedIfAbsent(ctx, "192.0.2.23", reason, "moderator", "", false)
		require.ErrorIs(t, err, ErrInvalidPolicyReason)
	}

	list, err := repo.GetWhitelistedIPs()
	require.NoError(t, err)
	require.Empty(t, list)
	excluded, err := repo.GetExcludedEntries()
	require.NoError(t, err)
	require.Empty(t, excluded)
}
