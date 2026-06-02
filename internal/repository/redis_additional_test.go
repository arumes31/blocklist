package repository

import (
	"context"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestRedisRepository_AdditionalCoverage(t *testing.T) {
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
		_ = redisContainer.Terminate(ctx)
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

	t.Run("HGetAllRaw and HDel", func(t *testing.T) {
		err := client.HSet(ctx, "test_hash", "field1", "value1").Err()
		assert.NoError(t, err)

		raw, err := repo.HGetAllRaw("test_hash")
		assert.NoError(t, err)
		assert.Equal(t, "value1", raw["field1"])

		err = repo.HDel("test_hash", "field1")
		assert.NoError(t, err)

		raw2, _ := repo.HGetAllRaw("test_hash")
		assert.Empty(t, raw2)
	})

	t.Run("GetBlockedIPs", func(t *testing.T) {
		// Clean ips key
		client.Del(ctx, "ips")

		entry1 := models.IPEntry{Reason: "r1"}
		entry2 := models.IPEntry{Reason: "r2"}
		_ = repo.BlockIP("1.1.1.1", entry1)
		_ = repo.BlockIP("2.2.2.2", entry2)

		blocked, err := repo.GetBlockedIPs()
		assert.NoError(t, err)
		assert.Len(t, blocked, 2)
		assert.Equal(t, "r1", blocked["1.1.1.1"].Reason)
	})

	t.Run("GetIPEntries", func(t *testing.T) {
		entries, err := repo.GetIPEntries([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
		assert.NoError(t, err)
		assert.Len(t, entries, 3)
		assert.NotNil(t, entries[0])
		assert.NotNil(t, entries[1])
		assert.Nil(t, entries[2]) // nonexistent
	})

	t.Run("RemoveIPTimestamp", func(t *testing.T) {
		_ = repo.IndexIPTimestamp("1.1.1.1", time.Now())
		err := repo.RemoveIPTimestamp("1.1.1.1")
		assert.NoError(t, err)

		card, _ := repo.GetZSetCount()
		assert.Equal(t, 0, card)
	})

	t.Run("ZRangeArgsWithScores", func(t *testing.T) {
		_ = repo.IndexIPTimestamp("1.1.1.1", time.Unix(100, 0))
		res, err := repo.ZRangeArgsWithScores(ctx, redis.ZRangeArgs{
			Key:   "ips_by_ts",
			Start: 0,
			Stop:  -1,
		})
		assert.NoError(t, err)
		assert.Len(t, res, 1)
		assert.Equal(t, float64(100), res[0].Score)
	})

	t.Run("UnblockIP", func(t *testing.T) {
		_ = repo.BlockIP("4.4.4.4", models.IPEntry{Reason: "x"})
		err := repo.UnblockIP("4.4.4.4")
		assert.NoError(t, err)

		e, _ := repo.GetIPEntry("4.4.4.4")
		assert.Nil(t, e)
	})

	t.Run("Whitelist Operations", func(t *testing.T) {
		err := repo.WhitelistIP("1.2.3.4", models.WhitelistEntry{Reason: "safe"})
		assert.NoError(t, err)

		wl, err := repo.GetWhitelistedIPs()
		assert.NoError(t, err)
		assert.Equal(t, "safe", wl["1.2.3.4"].Reason)

		err = repo.RemoveFromWhitelist("1.2.3.4")
		assert.NoError(t, err)

		wl2, _ := repo.GetWhitelistedIPs()
		assert.Empty(t, wl2)
	})

	t.Run("Excluded Operations", func(t *testing.T) {
		err := repo.AddExcluded("api.com", models.ExcludedEntry{Reason: "exempt"})
		assert.NoError(t, err)

		ex, err := repo.GetExcludedEntries()
		assert.NoError(t, err)
		assert.Equal(t, "exempt", ex["api.com"].Reason)

		err = repo.RemoveExcluded("api.com")
		assert.NoError(t, err)

		ex2, _ := repo.GetExcludedEntries()
		assert.Empty(t, ex2)
	})

	t.Run("Webhook Tracking", func(t *testing.T) {
		client.Del(ctx, "webhooks_by_ts")
		now := time.Now().UTC()
		err := repo.IndexWebhookHit(now)
		assert.NoError(t, err)

		cnt, err := repo.CountWebhooksLastHour()
		assert.NoError(t, err)
		assert.Equal(t, 1, cnt)
	})

	t.Run("Block Time and Minute Counts", func(t *testing.T) {
		client.Del(ctx, "ips_by_ts")
		now := time.Now().UTC()
		_ = repo.IndexIPTimestamp("1.1.1.1", now)

		tBlock, err := repo.GetLastBlockTime()
		assert.NoError(t, err)
		assert.Equal(t, now.Unix(), tBlock)

		cnt, err := repo.CountBlocksLastMinute()
		assert.NoError(t, err)
		assert.Equal(t, 1, cnt)
	})

	t.Run("Cache Operations", func(t *testing.T) {
		type cacheItem struct {
			Name string
			Age  int
		}
		item := cacheItem{Name: "Bob", Age: 30}
		err := repo.SetCache("my_key", item, time.Minute)
		assert.NoError(t, err)

		var retrieved cacheItem
		err = repo.GetCache("my_key", &retrieved)
		assert.NoError(t, err)
		assert.Equal(t, "Bob", retrieved.Name)
	})

	t.Run("Locking Operations", func(t *testing.T) {
		token, acquired, err := repo.AcquireLock("my_lock", time.Minute)
		assert.NoError(t, err)
		assert.True(t, acquired)
		assert.NotEmpty(t, token)

		// Second acquisition should fail
		_, acquired2, _ := repo.AcquireLock("my_lock", time.Minute)
		assert.False(t, acquired2)

		// Release lock
		err = repo.ReleaseLock("my_lock", token)
		assert.NoError(t, err)

		// Can acquire again
		_, acquired3, _ := repo.AcquireLock("my_lock", time.Minute)
		assert.True(t, acquired3)
	})

	t.Run("ExecBulkBlockAtomic and ExecBulkUnblockAtomic", func(t *testing.T) {
		client.Del(ctx, "ips")
		client.Del(ctx, "ips_by_ts")

		ips := []string{"10.0.0.1", "10.0.0.2"}
		entries := []models.IPEntry{
			{Reason: "bulk1"},
			{Reason: "bulk2"},
		}
		now := time.Now().UTC()

		err := repo.ExecBulkBlockAtomic(ips, entries, now)
		assert.NoError(t, err)

		c1, _ := repo.GetTrueRedisCount()
		assert.Equal(t, 2, c1)

		err = repo.ExecBulkUnblockAtomic(ips)
		assert.NoError(t, err)

		c2, _ := repo.GetTrueRedisCount()
		assert.Equal(t, 0, c2)
	})

	t.Run("Ban Count Helpers", func(t *testing.T) {
		client.Del(ctx, "ips_ban_counts")

		count, err := repo.IncrIPBanCount("8.8.8.8")
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count)

		count2, err := repo.GetIPBanCount("8.8.8.8")
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count2)

		counts, err := repo.GetIPBanCounts([]string{"8.8.8.8", "9.9.9.9"})
		assert.NoError(t, err)
		assert.Equal(t, int64(1), counts["8.8.8.8"])
		assert.Equal(t, int64(0), counts["9.9.9.9"])
	})

	t.Run("GetClient and Close", func(t *testing.T) {
		c := repo.GetClient()
		assert.NotNil(t, c)

		err := repo.Close()
		assert.NoError(t, err)
	})
}
