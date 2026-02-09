package service

import (
	"context"
	"strconv"
	"testing"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func setupServiceTest(t *testing.T) (*IPService, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	cfg := &config.Config{
		BlockedRanges: "10.0.0.0/8",
	}
	svc := NewIPService(cfg, rRepo, nil)
	return svc, mr
}

func TestListIPsPaginatedAdvanced_FilterCombinations(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Add test data with various attributes
	testIPs := []struct {
		ip      string
		reason  string
		addedBy string
		country string
		ts      time.Time
	}{
		{"1.2.3.4", "spam", "admin", "US", now.Add(-10 * time.Minute)},
		{"5.6.7.8", "brute_force", "bot", "CN", now.Add(-5 * time.Minute)},
		{"9.10.11.12", "spam", "admin", "US", now.Add(-2 * time.Minute)},
		{"13.14.15.16", "malware", "bot", "RU", now},
	}

	for _, td := range testIPs {
		entry := models.IPEntry{
			Timestamp: td.ts.Format("2006-01-02 15:04:05 UTC"),
			Reason:    td.reason,
			AddedBy:   td.addedBy,
			Geolocation: &models.GeoData{
				Country: td.country,
			},
		}
		svc.redisRepo.BlockIP(td.ip, entry)
		svc.redisRepo.IndexIPTimestamp(td.ip, td.ts)
	}

	t.Run("NoFilters", func(t *testing.T) {
		items, next, total, err := svc.ListIPsPaginatedAdvanced(ctx, 2, "", "", "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(items))
		assert.Equal(t, 4, total)
		assert.NotEmpty(t, next) // Should have cursor for pagination
	})

	t.Run("QueryFilter_IP", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "1.2.3", "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(items))
		assert.Equal(t, "1.2.3.4", items[0]["ip"])
	})

	t.Run("QueryFilter_Reason", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "spam", "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(items)) // Two IPs have spam reason
	})

	t.Run("QueryFilter_CIDR", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "1.2.3.0/24", "", "", "", "")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(items), 1) // Should match 1.2.3.4
		if len(items) > 0 {
			assert.Equal(t, "1.2.3.4", items[0]["ip"])
		}
	})

	t.Run("CountryFilter_Single", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "", "US", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(items)) // Two IPs from US
		for _, item := range items {
			data := item["data"].(*models.IPEntry)
			assert.Equal(t, "US", data.Geolocation.Country)
		}
	})

	t.Run("CountryFilter_Multiple", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "", "US,CN", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 3, len(items)) // Two US + one CN
	})

	t.Run("AddedByFilter", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "", "", "admin", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(items)) // Two added by admin
		for _, item := range items {
			data := item["data"].(*models.IPEntry)
			assert.Equal(t, "admin", data.AddedBy)
		}
	})

	t.Run("DateFilter_From", func(t *testing.T) {
		fromTime := now.Add(-6 * time.Minute)
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "", "", "", fromTime.Format(time.RFC3339), "")
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(items), 3) // Should exclude the -10 minute entry
	})

	t.Run("DateFilter_To", func(t *testing.T) {
		toTime := now.Add(-3 * time.Minute)
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "", "", "", "", toTime.Format(time.RFC3339))
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(items), 3) // Should exclude the most recent entry
	})

	t.Run("CombinedFilters", func(t *testing.T) {
		// Query for spam from US added by admin
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "spam", "US", "admin", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(items)) // Both spam IPs from US by admin
	})

	t.Run("PaginationWithCursor", func(t *testing.T) {
		// Get first page with limit 2
		items1, cursor1, _, err := svc.ListIPsPaginatedAdvanced(ctx, 2, "", "", "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(items1))
		assert.NotEmpty(t, cursor1)

		// Get second page
		items2, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 2, cursor1, "", "", "", "", "")
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(items2), 2)

		// Ensure no duplicates between pages
		if len(items2) > 0 {
			ip1 := items1[0]["ip"].(string)
			ip2 := items2[0]["ip"].(string)
			assert.NotEqual(t, ip1, ip2, "Should not have duplicate IPs across pages")
		}
	})

	t.Run("EmptyResult", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(ctx, 10, "", "", "XX", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 0, len(items))
	})
}

func TestExportIPs_LargeDataset(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Add 100 test IPs
	for i := 0; i < 100; i++ {
		ip := "192.168.1." + strconv.Itoa(i)
		reason := "spam"
		if i%3 == 0 {
			reason = "brute_force"
		}
		country := "US"
		if i%2 == 0 {
			country = "CN"
		}

		entry := models.IPEntry{
			Timestamp: now.Add(-time.Duration(i) * time.Minute).Format("2006-01-02 15:04:05 UTC"),
			Reason:    reason,
			AddedBy:   "auto",
			Geolocation: &models.GeoData{
				Country: country,
			},
		}
		svc.redisRepo.BlockIP(ip, entry)
		svc.redisRepo.IndexIPTimestamp(ip, now.Add(-time.Duration(i)*time.Minute))
	}

	t.Run("ExportAll", func(t *testing.T) {
		items, err := svc.ExportIPs(ctx, "", "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 100, len(items))
	})

	t.Run("ExportWithFilter", func(t *testing.T) {
		items, err := svc.ExportIPs(ctx, "", "US", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, 50, len(items)) // Half are US
	})

	t.Run("ExportWithQuery", func(t *testing.T) {
		items, err := svc.ExportIPs(ctx, "brute", "", "", "", "")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(items), 33) // About 1/3 have brute_force
	})

	t.Run("ExportWithDateRange", func(t *testing.T) {
		from := now.Add(-30 * time.Minute).Format(time.RFC3339)
		to := now.Add(-10 * time.Minute).Format(time.RFC3339)
		items, err := svc.ExportIPs(ctx, "", "", "", from, to)
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(items), 21) // IPs between -30 and -10 minutes
	})
}

func TestBulkBlock_EdgeCases(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()

	ctx := context.Background()

	t.Run("EmptyList", func(t *testing.T) {
		err := svc.BulkBlock(ctx, []string{}, "spam", "admin", "127.0.0.1", false, 0)
		assert.NoError(t, err)
	})

	t.Run("InvalidIPs", func(t *testing.T) {
		// Should skip invalid IPs without error
		err := svc.BulkBlock(ctx, []string{"invalid", "not-an-ip", "999.999.999.999"}, "spam", "admin", "127.0.0.1", false, 0)
		assert.NoError(t, err)

		// Verify none were blocked
		assert.False(t, svc.IsBlocked("invalid"))
	})

	t.Run("MixedValidInvalid", func(t *testing.T) {
		ips := []string{"1.2.3.4", "invalid", "5.6.7.8"}
		err := svc.BulkBlock(ctx, ips, "spam", "admin", "127.0.0.1", false, 0)
		assert.NoError(t, err)

		// Valid IPs should be blocked
		assert.True(t, svc.IsBlocked("1.2.3.4"))
		assert.True(t, svc.IsBlocked("5.6.7.8"))
	})

	t.Run("WithTTL", func(t *testing.T) {
		ips := []string{"11.0.0.1"}
		err := svc.BulkBlock(ctx, ips, "spam", "admin", "127.0.0.1", false, 3600) // 1 hour TTL
		assert.NoError(t, err)

		entry, _ := svc.redisRepo.GetIPEntry("11.0.0.1")
		assert.NotNil(t, entry)
		if entry != nil {
			assert.Equal(t, 3600, entry.TTL)
			assert.NotEmpty(t, entry.ExpiresAt)
		}
	})

	t.Run("PersistentBlocks", func(t *testing.T) {
		ips := []string{"20.0.0.1"}
		err := svc.BulkBlock(ctx, ips, "malware", "admin", "127.0.0.1", true, 0)
		assert.NoError(t, err)

		entry, _ := svc.redisRepo.GetIPEntry("20.0.0.1")
		assert.NotNil(t, entry)
		assert.Empty(t, entry.ExpiresAt) // Persistent should not have expiry
	})

	t.Run("LargeBatch", func(t *testing.T) {
		// Block 500 IPs
		ips := make([]string, 500)
		for i := 0; i < 500; i++ {
			ips[i] = "100." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + ".1"
		}

		err := svc.BulkBlock(ctx, ips, "bulk_spam", "admin", "127.0.0.1", false, 0)
		assert.NoError(t, err)

		// Verify a sample are blocked
		assert.True(t, svc.IsBlocked("100.0.0.1"))
		assert.True(t, svc.IsBlocked("100.1.243.1"))
	})
}

func TestBulkUnblock_EdgeCases(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()

	ctx := context.Background()

	// Setup: Block some IPs first
	blockIPs := []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}
	svc.BulkBlock(ctx, blockIPs, "spam", "admin", "127.0.0.1", false, 0)

	t.Run("EmptyList", func(t *testing.T) {
		err := svc.BulkUnblock(ctx, []string{}, "admin")
		assert.NoError(t, err)
	})

	t.Run("UnblockExisting", func(t *testing.T) {
		err := svc.BulkUnblock(ctx, []string{"1.2.3.4", "5.6.7.8"}, "admin")
		assert.NoError(t, err)

		// Give bloom filter sync time
		time.Sleep(100 * time.Millisecond)

		// Verify unblocked
		assert.False(t, svc.IsBlocked("1.2.3.4"))
		assert.False(t, svc.IsBlocked("5.6.7.8"))

		// Other IP should still be blocked
		assert.True(t, svc.IsBlocked("9.10.11.12"))
	})

	t.Run("UnblockNonExistent", func(t *testing.T) {
		// Should not error when unblocking non-existent IPs
		err := svc.BulkUnblock(ctx, []string{"99.99.99.99"}, "admin")
		assert.NoError(t, err)
	})

	t.Run("LargeBatchUnblock", func(t *testing.T) {
		// Block and then unblock many IPs
		ips := make([]string, 200)
		for i := 0; i < 200; i++ {
			ips[i] = "150." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + ".1"
		}

		svc.BulkBlock(ctx, ips, "spam", "admin", "127.0.0.1", false, 0)
		err := svc.BulkUnblock(ctx, ips, "admin")
		assert.NoError(t, err)

		// Give bloom filter sync time
		time.Sleep(200 * time.Millisecond)

		// Verify sample are unblocked
		assert.False(t, svc.IsBlocked("150.0.0.1"))
		assert.False(t, svc.IsBlocked("150.0.199.1"))
	})
}
