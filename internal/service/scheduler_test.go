package service

import (
	"blocklist/internal/repository"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestSchedulerService_CleanOldIPs_Persistent(t *testing.T) {
	// Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	// Parse addr
	host, port, _ := net.SplitHostPort(mr.Addr())
	p, _ := strconv.Atoi(port)

	redisRepo := repository.NewRedisRepository(host, p, "", 0)

	svc := NewSchedulerService(redisRepo, nil, nil)

	// Case 1: Persistent block (empty expires_at, old timestamp)
	ip1 := "1.1.1.1"
	entry1 := map[string]interface{}{
		"timestamp":  "2020-01-01 10:00:00 UTC",
		"expires_at": "",
		"reason":     "persistent",
	}
	val1, _ := json.Marshal(entry1)
	mr.HSet("ips", ip1, string(val1))
	_, _ = mr.ZAdd("ips_by_ts", 1577872800, ip1) // 2020-01-01

	// Case 2: Ephemeral block (expired)
	ip2 := "2.2.2.2"
	entry2 := map[string]interface{}{
		"timestamp":  "2020-01-01 10:00:00 UTC",
		"expires_at": "2020-01-02 10:00:00 UTC",
		"reason":     "expired",
	}
	val2, _ := json.Marshal(entry2)
	mr.HSet("ips", ip2, string(val2))
	_, _ = mr.ZAdd("ips_by_ts", 1577872800, ip2)

	// Run cleanup
	svc.CleanOldIPs("ips")

	// Verify Case 1 survives
	if mr.HGet("ips", ip1) == "" {
		t.Errorf("Persistent block %s was incorrectly deleted", ip1)
	}

	// Verify Case 2 deleted
	if mr.HGet("ips", ip2) != "" {
		t.Errorf("Expired ephemeral block %s was NOT deleted", ip2)
	}
}

func TestSchedulerService_CleanOldIPs_Whitelist(t *testing.T) {
	// Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	// Parse addr
	host, port, _ := net.SplitHostPort(mr.Addr())
	p, _ := strconv.Atoi(port)
	redisRepo := repository.NewRedisRepository(host, p, "", 0)
	svc := NewSchedulerService(redisRepo, nil, nil)

	// Helper to add entry
	addEntry := func(ip, expiresAt, timestamp string) {
		entry := map[string]string{
			"expires_at": expiresAt,
			"timestamp":  timestamp,
		}
		data, _ := json.Marshal(entry)
		_ = redisRepo.GetClient().HSet(context.Background(), "test_hash", ip, data)
	}

	// 1. Expired RFC3339
	expiredRFC := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	addEntry("1.1.1.1", expiredRFC, "")

	// 2. Expired Custom
	expiredCustom := time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04:05 UTC")
	addEntry("2.2.2.2", expiredCustom, "")

	// 3. Active RFC3339
	activeRFC := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	addEntry("3.3.3.3", activeRFC, "")

	// 4. Timestamp Fallback (Expired)
	tsExpired := time.Now().Add(-25 * time.Hour).Format(time.RFC3339)
	addEntry("4.4.4.4", "", tsExpired)

	svc.CleanOldIPs("test_hash")

	// Check results
	res, _ := redisRepo.GetClient().HGetAll(context.Background(), "test_hash").Result()

	if _, ok := res["1.1.1.1"]; ok {
		t.Error("Expired RFC3339 should be removed")
	}
	if _, ok := res["2.2.2.2"]; ok {
		t.Error("Expired Custom should be removed")
	}
	if _, ok := res["3.3.3.3"]; !ok {
		t.Error("Active RFC3339 should remain")
	}
	if _, ok := res["4.4.4.4"]; ok {
		t.Error("Expired Timestamp Fallback should be removed")
	}
}
