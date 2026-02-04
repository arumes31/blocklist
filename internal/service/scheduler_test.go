package service

import (
	"blocklist/internal/repository"
	"encoding/json"
	"net"
	"strconv"
	"testing"

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
	mr.ZAdd("ips_by_ts", 1577872800, ip1) // 2020-01-01

	// Case 2: Ephemeral block (expired)
	ip2 := "2.2.2.2"
	entry2 := map[string]interface{}{
		"timestamp":  "2020-01-01 10:00:00 UTC",
		"expires_at": "2020-01-02 10:00:00 UTC",
		"reason":     "expired",
	}
	val2, _ := json.Marshal(entry2)
	mr.HSet("ips", ip2, string(val2))
	mr.ZAdd("ips_by_ts", 1577872800, ip2)

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
