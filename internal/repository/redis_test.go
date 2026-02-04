package repository

import (
	"context"
	"testing"
	"time"

	"blocklist/internal/models"
	"github.com/redis/go-redis/v9"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestRedisRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Start Redis container
	redisContainer, err := tcredis.Run(ctx, "redis:alpine")
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}()

	uri, err := redisContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("failed to get connection string: %s", err)
	}

	opt, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatalf("failed to parse redis url: %s", err)
	}

	client := redis.NewClient(opt)
	repo := &RedisRepository{
		client: client,
		ctx:    ctx,
	}

	t.Run("BlockAndGetIP", func(t *testing.T) {
		ip := "1.2.3.4"
		entry := models.IPEntry{
			Timestamp: "2026-01-31 12:00:00 UTC",
			Reason:    "test-reason",
			AddedBy:   "test-user",
		}

		err := repo.BlockIP(ip, entry)
		if err != nil {
			t.Errorf("BlockIP failed: %v", err)
		}

		got, err := repo.GetIPEntry(ip)
		if err != nil {
			t.Errorf("GetIPEntry failed: %v", err)
		}
		if got.Reason != entry.Reason {
			t.Errorf("expected reason %s, got %s", entry.Reason, got.Reason)
		}
	})

	t.Run("Pagination", func(t *testing.T) {
		now := time.Now().UTC()
		_ = repo.IndexIPTimestamp("1.1.1.1", now.Add(-10*time.Second))
		_ = repo.IndexIPTimestamp("2.2.2.2", now.Add(-5*time.Second))
		_ = repo.IndexIPTimestamp("3.3.3.3", now)

		card, _ := client.ZCard(ctx, "ips_by_ts").Result()
		t.Logf("ZCard(ips_by_ts) = %d", card)

		zs, next, err := repo.ZPageByScoreDesc(2, "")
		if err != nil {
			t.Fatalf("ZPageByScoreDesc failed: %v", err)
		}
		
		t.Logf("Fetched %d items, next cursor: %s", len(zs), next)
		for i, z := range zs {
			t.Logf("  [%d] %s (score: %v)", i, z.Member.(string), z.Score)
		}

		if len(zs) == 0 {
			t.Fatal("expected items, got 0")
		}

		if zs[0].Member.(string) != "3.3.3.3" {
			t.Errorf("expected 3.3.3.3 as first item, got %s", zs[0].Member.(string))
		}
		if next == "" {
			t.Error("expected next cursor, got empty")
		}

		// Test cursor stability
		zs2, _, err := repo.ZPageByScoreDesc(2, next)
		if err != nil {
			t.Fatalf("ZPageByScoreDesc with cursor failed: %v", err)
		}
		
		t.Logf("Fetched %d items for next page", len(zs2))
		if len(zs2) == 0 {
			t.Fatal("expected 1 item from next page, got 0")
		}

		if zs2[0].Member.(string) != "1.1.1.1" {
			t.Errorf("expected 1.1.1.1 as next item, got %s", zs2[0].Member.(string))
		}
	})

	t.Run("AtomicOperations", func(t *testing.T) {
		ip := "8.8.8.8"
		entry := models.IPEntry{
			Timestamp: "2026-01-31 15:00:00 UTC",
			Reason:    "atomic-test",
			AddedBy:   "bot",
			Geolocation: &models.GeoData{Country: "US"},
		}
		now := time.Now().UTC()

		err := repo.ExecBlockAtomic(ip, entry, now)
		if err != nil {
			t.Errorf("ExecBlockAtomic failed: %v", err)
		}

		// Verify side effects
		got, _ := repo.GetIPEntry(ip)
		if got == nil || got.Reason != "atomic-test" {
			t.Error("Block not persisted in hash")
		}

		score, _ := client.ZScore(ctx, "ips_by_ts", ip).Result()
		if score == 0 {
			t.Error("Block not indexed in ZSET")
		}

		// Test Unblock
		err = repo.ExecUnblockAtomic(ip)
		if err != nil {
			t.Errorf("ExecUnblockAtomic failed: %v", err)
		}
		got2, _ := repo.GetIPEntry(ip)
		if got2 != nil {
			t.Error("IP still exists after atomic unblock")
		}
	})
}
