package service

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

func newAuditTestService(t *testing.T, cfg *config.Config) (*IPService, *repository.RedisRepository, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	port, err := strconv.Atoi(mr.Port())
	require.NoError(t, err)
	repo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	t.Cleanup(func() { _ = repo.Close() })
	if cfg == nil {
		cfg = &config.Config{}
	}
	return NewIPService(cfg, repo, nil), repo, mr
}

// A block written by another server process must be enforced at once: no
// process-local cache may report an address as not blocked.
func TestIPService_IsBlockedSeesBlocksFromOtherProcesses(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuditTestService(t, nil)
	require.False(t, svc.IsBlocked("192.0.2.1"))
	require.NoError(t, repo.BlockIP("192.0.2.1", models.IPEntry{Reason: "peer process"}))
	require.True(t, svc.IsBlocked("192.0.2.1"))
}

// Expiry removal must not delete a renewal written after the expired record
// was read; the conditional removal leaves the newer record in place.
func TestIPService_ExpiryRemovalKeepsRenewal(t *testing.T) {
	t.Parallel()
	_, repo, mr := newAuditTestService(t, nil)
	past := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05 UTC")
	future := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05 UTC")
	require.NoError(t, repo.BlockIP("192.0.2.9", models.IPEntry{Timestamp: "2026-01-01 00:00:01 UTC", ExpiresAt: future}))

	result, err := repo.RemoveIfUnchanged("ips", "192.0.2.9", "2026-01-01 00:00:00 UTC", past)
	require.NoError(t, err)
	require.Equal(t, repository.RemoveChanged, result)
	require.NotEmpty(t, mr.HGet("ips", "192.0.2.9"), "renewal must survive")

	result, err = repo.RemoveIfUnchanged("ips", "192.0.2.9", "2026-01-01 00:00:01 UTC", future)
	require.NoError(t, err)
	require.Equal(t, repository.RemoveDone, result)
	require.Empty(t, mr.HGet("ips", "192.0.2.9"))
}

// A block-only caller must not shorten or end an existing longer block.
func TestIPService_BlockNeverShortensExistingBlock(t *testing.T) {
	t.Parallel()
	svc, _, mr := newAuditTestService(t, nil)
	ctx := context.Background()

	_, err := svc.BlockIP(ctx, "192.0.2.20", "permanent", "admin", "", true, 0)
	require.NoError(t, err)
	_, err = svc.BlockIP(ctx, "192.0.2.20", "short", "operator", "", false, time.Minute)
	require.ErrorIs(t, err, ErrBlockShortens)
	require.Contains(t, mr.HGet("ips", "192.0.2.20"), "permanent")

	_, err = svc.BlockIP(ctx, "192.0.2.21", "long", "admin", "", false, 48*time.Hour)
	require.NoError(t, err)
	_, err = svc.BlockIP(ctx, "192.0.2.21", "short", "operator", "", false, time.Minute)
	require.ErrorIs(t, err, ErrBlockShortens)
	_, err = svc.BlockIP(ctx, "192.0.2.21", "longer", "operator", "", false, 72*time.Hour)
	require.NoError(t, err, "extending a block stays allowed")

	// Bulk replacement keeps the longer block too.
	require.NoError(t, svc.BulkBlock(ctx, []string{"192.0.2.20", "192.0.2.22"}, "bulk", "operator", "", false, 60))
	require.Contains(t, mr.HGet("ips", "192.0.2.20"), "permanent")
	require.NotEmpty(t, mr.HGet("ips", "192.0.2.22"))
}

// Mapped IPv4 spellings must be stored canonically and cannot bypass
// protected ranges, mapped CIDR exclusions or mapped CIDR whitelist entries.
func TestIPService_MappedAddressesUseOneFamily(t *testing.T) {
	t.Parallel()
	svc, repo, mr := newAuditTestService(t, &config.Config{BlockedRanges: "10.0.0.0/8"})
	ctx := context.Background()

	_, err := svc.BlockIP(ctx, "::ffff:10.1.2.3", "protected", "operator", "", false, time.Hour)
	require.Error(t, err, "a mapped spelling of a protected address must be refused")

	require.NoError(t, svc.AddExcluded(ctx, "::ffff:198.51.100.0/120", "mapped exclusion", "admin", "", false))
	entries, err := repo.GetExcludedEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "198.51.100.0/24", "mapped prefixes are stored as IPv4")
	_, err = svc.BlockIP(ctx, "198.51.100.7", "excluded", "operator", "", false, time.Hour)
	require.Error(t, err)

	require.NoError(t, svc.WhitelistIP(ctx, "::ffff:203.0.113.0/120", "mapped whitelist", "admin", ""))
	_, err = svc.BlockIP(ctx, "203.0.113.5", "whitelisted", "operator", "", false, time.Hour)
	require.Error(t, err)

	// Legacy records stored in the mapped form still protect IPv4 addresses.
	mr.HSet("ips_webhook2_excluded", "::ffff:192.0.2.0/120", `{"value":"::ffff:192.0.2.0/120","type":"cidr"}`)
	_, err = svc.BlockIP(ctx, "192.0.2.77", "legacy excluded", "operator", "", false, time.Hour)
	require.Error(t, err)

	_, err = svc.BlockIP(ctx, "::ffff:198.18.0.1", "canonical", "operator", "", false, time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, mr.HGet("ips", "198.18.0.1"), "blocks are stored under the canonical address")
	require.Empty(t, mr.HGet("ips", "::ffff:198.18.0.1"))
}

// Zoned addresses and reasons PostgreSQL cannot store are rejected before any
// enforcement change.
func TestIPService_RejectsZonesAndUnstorableReasons(t *testing.T) {
	t.Parallel()
	svc, _, mr := newAuditTestService(t, nil)
	ctx := context.Background()

	_, err := svc.BlockIP(ctx, "fe80::1%eth0\n198.51.100.1", "zone", "operator", "", false, time.Hour)
	require.Error(t, err)
	_, err = svc.BlockIP(ctx, "192.0.2.30", "nul\x00reason", "operator", "", false, time.Hour)
	require.ErrorIs(t, err, ErrInvalidBlockInput)
	require.ErrorIs(t, svc.BulkBlock(ctx, []string{"192.0.2.31"}, "nul\x00", "operator", "", false, 60), ErrInvalidBlockInput)

	require.NoError(t, svc.BulkBlock(ctx, []string{"fe80::1%eth0\n198.51.100.1", "192.0.2.32"}, "bulk", "operator", "", false, 60))
	keys, err := mr.HKeys("ips")
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.32"}, keys)
	require.ErrorIs(t, svc.BulkUnblock(ctx, []string{"not-an-ip\x00"}, "operator"), ErrInvalidBlockInput)
}

// The DNS refresh must not resurrect a deleted exclusion or overwrite an edit
// made while it was resolving.
func TestIPService_ResolutionUpdateIsConditional(t *testing.T) {
	t.Parallel()
	svc, repo, mr := newAuditTestService(t, nil)
	ctx := context.Background()
	require.NoError(t, svc.AddExcluded(ctx, "host.example.test", "original", "admin", "", false))
	entries, err := repo.GetExcludedEntries()
	require.NoError(t, err)
	snapshot := entries["host.example.test"]

	resolved := snapshot
	resolved.ResolvedIPs = []string{"192.0.2.1"}
	resolved.ResolvedAt = "2026-11-03 00:00:00 UTC"

	// Operator edit between snapshot and write: the refresh result is dropped.
	edited := snapshot
	edited.Reason = "edited"
	require.NoError(t, repo.AddExcluded("host.example.test", edited))
	updated, err := repo.UpdateExcludedResolution("host.example.test", resolved)
	require.NoError(t, err)
	require.False(t, updated)
	require.Contains(t, mr.HGet("ips_webhook2_excluded", "host.example.test"), "edited")

	// Deleted exclusion: the refresh must not recreate it.
	require.NoError(t, repo.RemoveExcluded("host.example.test"))
	updated, err = repo.UpdateExcludedResolution("host.example.test", resolved)
	require.NoError(t, err)
	require.False(t, updated)
	require.Empty(t, mr.HGet("ips_webhook2_excluded", "host.example.test"))

	// Unchanged exclusion: only the resolution fields are written.
	require.NoError(t, repo.AddExcluded("host.example.test", snapshot))
	updated, err = repo.UpdateExcludedResolution("host.example.test", resolved)
	require.NoError(t, err)
	require.True(t, updated)
	require.Contains(t, mr.HGet("ips_webhook2_excluded", "host.example.test"), "192.0.2.1")
}

// Feed refreshes never replace an operator-owned exclusion, checked atomically.
func TestIPService_SystemExclusionKeepsOperatorEntries(t *testing.T) {
	t.Parallel()
	svc, _, mr := newAuditTestService(t, nil)
	ctx := context.Background()
	require.NoError(t, svc.AddExcluded(ctx, "192.0.2.50", "operator", "admin", "", true))

	written, err := svc.AddSystemExcluded(ctx, "192.0.2.50", "External Source: feed", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	require.NoError(t, err)
	require.False(t, written)
	require.Contains(t, mr.HGet("ips_webhook2_excluded", "192.0.2.50"), `"added_by":"admin"`)

	written, err = svc.AddSystemExcluded(ctx, "192.0.2.51", "External Source: feed", "")
	require.NoError(t, err)
	require.True(t, written)
	written, err = svc.AddSystemExcluded(ctx, "192.0.2.51", "External Source: feed", "")
	require.NoError(t, err)
	require.True(t, written, "feed entries renew their own records")
}

func TestIPService_CountryFilterIsBoundedSet(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuditTestService(t, nil)
	opts := svc.prepareFilterOptions("", strings.Repeat("AT,", 5000)+"DE", "", "", "")
	require.Len(t, opts.countries, 2, "duplicates collapse into one set entry")

	entry := &models.IPEntry{Geolocation: &models.GeoData{Country: "DE"}}
	require.True(t, svc.matchesFilters("192.0.2.1", entry, opts))
	entry.Geolocation.Country = "US"
	require.False(t, svc.matchesFilters("192.0.2.1", entry, opts))
}

func TestIPService_IsBlockedCanonicalizesLookup(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuditTestService(t, nil)
	require.NoError(t, repo.BlockIP("192.0.2.40", models.IPEntry{Reason: "canonical"}))
	require.True(t, svc.IsBlocked("::ffff:192.0.2.40"))
}
