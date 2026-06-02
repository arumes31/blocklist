package service

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestIPService_CoverageAdditional(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	cfg := &config.Config{
		BlockedRanges: "10.0.0.0/8,172.16.0.0/12",
	}
	svc := NewIPService(cfg, rRepo, nil)
	ctx := context.Background()

	t.Run("UnblockIP", func(t *testing.T) {
		ip := "192.168.1.5"
		// Block it first
		_, err := svc.BlockIP(ctx, ip, "abuse", "admin", "127.0.0.1", false, time.Hour)
		assert.NoError(t, err)
		assert.True(t, svc.IsBlocked(ip))

		// Unblock it
		err = svc.UnblockIP(ctx, ip, "admin")
		assert.NoError(t, err)
		assert.False(t, svc.IsBlocked(ip))
	})

	t.Run("WhitelistIP and RemoveWhitelist", func(t *testing.T) {
		ip := "192.168.2.1"
		err := svc.WhitelistIP(ctx, ip, "approved", "admin", "")
		assert.NoError(t, err)

		// Whitelisted IP should not be valid for blocking
		assert.False(t, svc.IsValidIP(ip))

		err = svc.RemoveWhitelist(ctx, ip, "admin")
		assert.NoError(t, err)
		assert.True(t, svc.IsValidIP(ip))
	})

	t.Run("GetIPDetails", func(t *testing.T) {
		ip := "192.168.3.1"
		_, err := svc.BlockIP(ctx, ip, "abuse", "admin", "127.0.0.1", false, time.Hour)
		assert.NoError(t, err)

		details, err := svc.GetIPDetails(ctx, ip)
		assert.NoError(t, err)
		assert.Equal(t, ip, details["ip"])
		assert.NotNil(t, details["current"])
	})

	t.Run("GetExcludedCount", func(t *testing.T) {
		count := svc.GetExcludedCount(ctx)
		assert.Equal(t, 0, count)

		err := svc.AddExcluded(ctx, "192.168.4.0/24", "exempt", "admin", "")
		assert.NoError(t, err)

		count = svc.GetExcludedCount(ctx)
		assert.Equal(t, 1, count)
	})

	t.Run("ExclusionConflicts", func(t *testing.T) {
		// Conflict: falling within blocked range
		warns1 := svc.ExclusionConflicts(ctx, "10.0.0.5")
		assert.Contains(t, warns1[0], "falls within configured blocked range")

		// Conflict: covered by existing excluded subnet
		_ = svc.AddExcluded(ctx, "192.168.10.0/24", "subnet", "admin", "")
		warns2 := svc.ExclusionConflicts(ctx, "192.168.10.5")
		assert.Contains(t, warns2[0], "is already covered by excluded subnet")

		// Conflict: currently blocked
		_ = svc.redisRepo.BlockIP("1.1.1.1", models.IPEntry{Reason: "test"})
		warns3 := svc.ExclusionConflicts(ctx, "1.1.1.1")
		assert.Contains(t, warns3[0], "is currently blocked")

		// Conflict: covers blocked IP
		_ = svc.redisRepo.BlockIP("192.168.20.50", models.IPEntry{Reason: "test"})
		warns4 := svc.ExclusionConflicts(ctx, "192.168.20.0/24")
		assert.Contains(t, warns4[0], "covers 1 currently blocked IPs")

		// Conflict: already exists
		warns5 := svc.ExclusionConflicts(ctx, "192.168.10.0/24")
		assert.Contains(t, warns5[0], "is already on the excluded list")
	})

	t.Run("FQDN & Wildcard resolving failure paths", func(t *testing.T) {
		// Non-existent or fake wildcard name
		assert.False(t, svc.matchWildcard("*.nonexistent-domain-fake-123.com", netip.MustParseAddr("1.2.3.4")))

		// resolveFQDN for non-existent domain should return empty set
		res := svc.resolveFQDN("nonexistent-domain-fake-123.com")
		assert.Empty(t, res)

		// RefreshExcludedFQDNs
		_ = svc.AddExcluded(ctx, "nonexistent-domain-fake-123.com", "fake domain", "admin", "")
		svc.RefreshExcludedFQDNs(ctx)
		// Should not crash and should work normally
	})

	t.Run("ReloadReaders", func(t *testing.T) {
		// Check that ReloadReaders doesn't panic
		assert.NotPanics(t, func() {
			svc.ReloadReaders()
		})
	})
}
