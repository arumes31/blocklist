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

		h, d, total, active, _, _, _, wh, lb, bm, err := svc.Stats(ctx)
		if err != nil {
			t.Fatalf("Stats failed: %v", err)
		}
		if active != 1 {
			t.Errorf("expected active 1, got %d", active)
		}
		// h and d might be 0 because we didn't update buckets or ZSET in this manual call
		_ = h; _ = d; _ = wh; _ = lb; _ = bm; _ = total
	})

	t.Run("BulkBlock_Logic", func(t *testing.T) {
		ips := []string{"8.8.8.8", "8.8.4.4", "10.0.0.1"} // 10.0.0.1 is in blocked range
		err := svc.BulkBlock(context.Background(), ips, "bulk-test", "admin", "127.0.0.1", false, 3600)
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

	t.Run("CalculateThreatScore", func(t *testing.T) {
		// Case 1: SSH Brute Force, 0 prior bans
		score1 := svc.CalculateThreatScore("1.1.1.1", "SSH brute force attempt")
		if score1 != 20 {
			t.Errorf("expected score 20 for ssh brute force (0 prior), got %d", score1)
		}

		// Case 2: SQL Injection, 2 prior bans
		mr.HSet("ips_ban_counts", "2.2.2.2", "2")
		score2 := svc.CalculateThreatScore("2.2.2.2", "Detected SQL Injection")
		// Base: 2 * 10 = 20. Bonus: 40. Total: 60.
		if score2 != 60 {
			t.Errorf("expected score 60 for sql injection (2 prior), got %d", score2)
		}

		// Case 3: Spam, 5 prior bans
		mr.HSet("ips_ban_counts", "3.3.3.3", "5")
		score3 := svc.CalculateThreatScore("3.3.3.3", "Spam bot")
		// Base: 5 * 10 = 50. Bonus: 15. Total: 65.
		if score3 != 65 {
			t.Errorf("expected score 65 for spam (5 prior), got %d", score3)
		}

		// Case 4: Cap at 100
		mr.HSet("ips_ban_counts", "4.4.4.4", "20") // 200 base
		score4 := svc.CalculateThreatScore("4.4.4.4", "generic")
		if score4 != 100 {
			t.Errorf("expected score 100 (capped), got %d", score4)
		}
	})
}