package service

import (
	"context"
	"strconv"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"github.com/alicebob/miniredis/v2"
)

func TestIPService_Enhanced(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	cfg := &config.Config{
		BlockedRanges: "10.0.0.0/8",
	}
	svc := NewIPService(cfg, rRepo, nil)

	t.Run("IsValidIP_WithWhitelist", func(t *testing.T) {
		ip := "1.1.1.1"
		// Initially valid
		if !svc.IsValidIP(ip) {
			t.Errorf("expected %s to be valid", ip)
		}

		// Add to whitelist in miniredis
		_ = rRepo.WhitelistIP(ip, models.WhitelistEntry{Reason: "test"})
		
		// Now should be invalid
		if svc.IsValidIP(ip) {
			t.Errorf("expected %s to be invalid after whitelisting", ip)
		}
	})

	t.Run("Stats_Calculation", func(t *testing.T) {
		ctx := context.Background()
		// Mock some data
		entry := models.IPEntry{Reason: "test", Timestamp: "2026-01-31 12:00:00 UTC"}
		_ = rRepo.BlockIP("1.2.3.4", entry)

		h, d, total, _, _, _, wh, lb, bm, err := svc.Stats(ctx)
		if err != nil {
			t.Fatalf("Stats failed: %v", err)
		}
		if total != 1 {
			t.Errorf("expected total 1, got %d", total)
		}
		// h and d might be 0 because we didn't update buckets or ZSET in this manual call
		_ = h; _ = d; _ = wh; _ = lb; _ = bm
	})

	t.Run("BulkBlock_Logic", func(t *testing.T) {
		ips := []string{"8.8.8.8", "8.8.4.4", "10.0.0.1"} // 10.0.0.1 is in blocked range
		err := svc.BulkBlock(context.Background(), ips, "bulk-test", "admin", false, 3600)
		if err != nil {
			t.Fatalf("BulkBlock failed: %v", err)
		}

		// 10.0.0.1 should NOT be blocked
		if mr.HGet("ips", "10.0.0.1") != "" {
			t.Error("10.0.0.1 should not have been blocked (in blocked range)")
		}
		
		// 8.8.8.8 SHOULD be blocked
		if mr.HGet("ips", "8.8.8.8") == "" {
			t.Error("8.8.8.8 should have been blocked")
		}
	})
}