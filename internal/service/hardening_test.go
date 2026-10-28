package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhitelistCIDRProtectsMemberAddresses(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, svc.WhitelistIP(ctx, "203.0.113.77/24", "office", "alice", ""))
	assert.False(t, svc.IsValidIP("203.0.113.9"), "member of a whitelisted subnet must not be blockable")
	assert.True(t, svc.IsValidIP("198.51.100.9"))

	require.NoError(t, svc.WhitelistIP(ctx, "2001:DB8:0:0::1", "v6", "alice", ""))
	assert.False(t, svc.IsValidIP("2001:db8::1"), "non-canonical IPv6 input is stored canonically")
}

func TestCreateOnlyWritesNeverReplaceEntries(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	ctx := context.Background()

	created, err := svc.WhitelistIPIfAbsent(ctx, "198.51.100.7", "first", "moderator", "")
	require.NoError(t, err)
	assert.True(t, created)
	created, err = svc.WhitelistIPIfAbsent(ctx, "198.51.100.7", "second", "moderator", "2099-01-01T00:00:00Z")
	require.NoError(t, err)
	assert.False(t, created)
	entries, err := svc.redisRepo.GetWhitelistedIPs()
	require.NoError(t, err)
	assert.Equal(t, "first", entries["198.51.100.7"].Reason)
	assert.Empty(t, entries["198.51.100.7"].ExpiresAt)

	created, err = svc.AddExcludedIfAbsent(ctx, "192.0.2.9/24", "first", "moderator", "", false)
	require.NoError(t, err)
	assert.True(t, created)
	created, err = svc.AddExcludedIfAbsent(ctx, "192.0.2.0/24", "second", "moderator", "", false)
	require.NoError(t, err)
	assert.False(t, created, "canonical forms collide")
}

func TestOnlyIPsAndPrefixes(t *testing.T) {
	assert.Equal(t,
		[]string{"192.0.2.1", "2001:db8::/32"},
		onlyIPsAndPrefixes([]string{"192.0.2.1", "attacker.example", "*.example.com", " 2001:db8::/32 ", ""}),
	)
}

func TestExternalSourceKeepsOperatorExclusions(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	ctx := context.Background()
	require.NoError(t, svc.AddExcluded(ctx, "192.0.2.0/24", "operator", "alice", "", false))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["192.0.2.0/24", "198.51.100.0/24", "attacker.example"]`))
	}))
	defer server.Close()
	ext := NewExternalSourceService(nil, svc)
	ext.client = newTestClient(server)
	require.NoError(t, ext.RefreshSource(ctx, models.ExternalSource{ID: 1, Name: "feed", URL: "http://example.com/feed", SourceType: "json_cidr"}))

	entries, err := svc.redisRepo.GetExcludedEntries()
	require.NoError(t, err)
	assert.Equal(t, "alice", entries["192.0.2.0/24"].AddedBy, "operator entry is not replaced by the feed")
	assert.Empty(t, entries["192.0.2.0/24"].ExpiresAt)
	assert.Equal(t, "system", entries["198.51.100.0/24"].AddedBy)
	assert.NotContains(t, entries, "attacker.example", "non-address feed entries are dropped")
}
