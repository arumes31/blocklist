package service

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/stretchr/testify/require"
)

func TestIPService_BloomSyncDoesNotHoldLockDuringRedisRead(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	port, err := strconv.Atoi(mr.Port())
	require.NoError(t, err)
	repo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	t.Cleanup(func() { _ = repo.Close() })
	svc := NewIPService(&config.Config{}, repo, nil)
	// Simulate a record not yet represented in this process's Bloom filter.
	require.NoError(t, repo.BlockIP("192.0.2.1", models.IPEntry{Reason: "existing"}))

	reading, release, synced := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	mr.Server().SetPreHook(func(_ *server.Peer, command string, args ...string) bool {
		if command == "HGETALL" && len(args) == 1 && args[0] == "ips" {
			close(reading)
			<-release
		}
		return false
	})
	go func() {
		svc.syncBloomFilter()
		close(synced)
	}()
	t.Cleanup(func() {
		unblock()
		<-synced
	})
	select {
	case <-reading:
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not start reading Redis")
	}

	// A negative filter result is unsafe during sync: confirm against Redis
	// rather than waiting on the snapshot or incorrectly returning false.
	blocked := make(chan bool, 1)
	go func() { blocked <- svc.IsBlocked("192.0.2.1") }()
	select {
	case got := <-blocked:
		require.True(t, got)
	case <-time.After(2 * time.Second):
		t.Fatal("IsBlocked waited for the unrelated Redis snapshot")
	}

	added := make(chan error, 1)
	go func() {
		_, err := svc.BlockIP(context.Background(), "192.0.2.2", "concurrent", "test", "", false, time.Hour)
		added <- err
	}()
	select {
	case err := <-added:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("BlockIP waited for the unrelated Redis snapshot")
	}
	unblock()
	<-synced
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		require.True(t, svc.IsBlocked(ip), "lost concurrent block: %s", ip)
	}
	require.False(t, svc.IsBlocked("192.0.2.3"))
}
