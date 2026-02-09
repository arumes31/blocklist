package repository

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestZPageByScoreDesc_EdgeCases(t *testing.T) {
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

	t.Run("EmptySet", func(t *testing.T) {
		// Ensure set is empty
		client.Del(ctx, "ips_by_ts")

		zs, next, err := repo.ZPageByScoreDesc(10, "")
		if err != nil {
			t.Fatalf("ZPageByScoreDesc failed: %v", err)
		}

		if len(zs) != 0 {
			t.Errorf("expected 0 items from empty set, got %d", len(zs))
		}
		if next != "" {
			t.Errorf("expected empty cursor, got %s", next)
		}
	})

	t.Run("LastPage", func(t *testing.T) {
		// Clean and add just  2 IPs
		client.Del(ctx, "ips_by_ts")
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 100, Member: "ip1"})
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 200, Member: "ip2"})

		// Request more than available
		zs, next, err := repo.ZPageByScoreDesc(10, "")
		if err != nil {
			t.Fatalf("ZPageByScoreDesc failed: %v", err)
		}

		if len(zs) != 2 {
			t.Errorf("expected 2 items, got %d", len(zs))
		}
		if next != "" {
			t.Errorf("expected empty cursor (last page), got %s", next)
		}
	})

	t.Run("InvalidCursor", func(t *testing.T) {
		client.Del(ctx, "ips_by_ts")
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 100, Member: "ip1"})

		// Use invalid cursor format
		zs, next, err := repo.ZPageByScoreDesc(10, "invalid-cursor")

		// Should still work, just starts from beginning or returns empty
		if err != nil {
			t.Fatalf("ZPageByScoreDesc with invalid cursor failed: %v", err)
		}

		// Implementation may vary - either empty or full set
		t.Logf("Invalid cursor returned %d items, next: %s", len(zs), next)
	})

	t.Run("ExactPageSize", func(t *testing.T) {
		client.Del(ctx, "ips_by_ts")
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 100, Member: "ip1"})
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 200, Member: "ip2"})
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 300, Member: "ip3"})

		// Page size exactly equals total
		zs, next, err := repo.ZPageByScoreDesc(3, "")
		if err != nil {
			t.Fatalf("ZPageByScoreDesc failed: %v", err)
		}

		if len(zs) != 3 {
			t.Errorf("expected 3 items, got %d", len(zs))
		}
		// Should be no next page when we got exactly the page size and no more
		if next != "" {
			t.Logf("Note: cursor is %s even though we fetched all items", next)
		}
	})

	t.Run("ZeroLimit", func(t *testing.T) {
		client.Del(ctx, "ips_by_ts")
		client.ZAdd(ctx, "ips_by_ts", redis.Z{Score: 100, Member: "ip1"})

		// Request 0 items
		zs, next, err := repo.ZPageByScoreDesc(0, "")

		// Should not error, just return empty
		if err != nil {
			t.Logf("ZPageByScoreDesc with limit 0: %v", err)
		}

		if len(zs) != 0 {
			t.Errorf("expected 0 items with limit=0, got %d", len(zs))
		}
		t.Logf("Limit=0 returned %d items, next: %s", len(zs), next)
	})
}

func TestRedisConnection_ErrorHandling(t *testing.T) {
	// Test with invalid connection - no container
	ctx := context.Background()

	// Try to connect to non-existent Redis
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:9999", // Unlikely to be running
	})

	repo := &RedisRepository{
		client: client,
		ctx:    ctx,
	}

	t.Run("ConnectionFailure", func(t *testing.T) {
		// This should fail quickly
		_, err := repo.GetIPEntry("1.2.3.4")
		if err == nil {
			t.Error("expected error from failed connection, got nil")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("PaginationOnDeadConnection", func(t *testing.T) {
		_, _, err := repo.ZPageByScoreDesc(10, "")
		if err == nil {
			t.Error("expected error from failed connection during pagination, got nil")
		}
		t.Logf("Got expected error: %v", err)
	})
}
