package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"blocklist/internal/models"
	"github.com/stretchr/testify/require"
)

func TestStatsSnapshotReusesReadsAndOwnsResults(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	entry := models.IPEntry{Reason: "scanner", Geolocation: &models.GeoData{Country: "AT", ASN: 64512, ASNOrg: "fixture"}}
	require.NoError(t, svc.redisRepo.BlockIP("198.18.0.1", entry))
	_, _, _, active, countries, asns, reasons, _, _, _, _, err := svc.Stats(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, active)
	before := mr.CommandCount()
	countries[0].Count = 999
	asns[0].Count = 999
	reasons[0].Count = 999
	_, _, _, _, countries, asns, reasons, _, _, _, _, err = svc.Stats(context.Background())
	require.NoError(t, err)
	require.Equal(t, before, mr.CommandCount(), "a fresh snapshot must not reread Redis")
	require.Equal(t, 1, countries[0].Count)
	require.Equal(t, 1, asns[0].Count)
	require.Equal(t, 1, reasons[0].Count)
}

func TestStatsSnapshotCoalescesConcurrentRefresh(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	require.NoError(t, svc.redisRepo.BlockIP("198.18.0.1", models.IPEntry{Reason: "scanner"}))
	before := mr.CommandCount()
	_, _, _, _, _, _, _, _, _, _, _, err := (&IPService{redisRepo: svc.redisRepo}).Stats(context.Background())
	require.NoError(t, err)
	singleRead := mr.CommandCount() - before
	before = mr.CommandCount()
	start := make(chan struct{})
	errors := make(chan error, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, _, _, _, _, _, _, _, _, _, err := svc.Stats(context.Background())
			errors <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.Equal(t, singleRead, mr.CommandCount()-before, "concurrent readers must share one refresh")
}

func TestStatsSnapshotRespectsCancellation(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, _, _, _, _, _, _, _, err := svc.Stats(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStatsSnapshotRefreshesExpiredDataAndRetriesErrors(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	ctx := context.Background()
	require.NoError(t, svc.redisRepo.BlockIP("198.18.0.1", models.IPEntry{Reason: "old"}))
	_, _, _, active, _, _, _, _, _, _, _, err := svc.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, active)
	require.NoError(t, svc.redisRepo.BlockIP("198.18.0.2", models.IPEntry{Reason: "new"}))
	_, _, _, active, _, _, _, _, _, _, _, err = svc.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, active, "display snapshot may lag writes within its documented TTL")
	svc.statsMu.Lock()
	svc.statsCached.expires = time.Now().Add(-time.Second)
	svc.statsMu.Unlock()
	mr.SetError("ERR temporary failure")
	_, _, _, _, _, _, _, _, _, _, _, err = svc.Stats(ctx)
	require.Error(t, err, "expired snapshots must not hide refresh failures")
	mr.SetError("")
	_, _, _, active, _, _, _, _, _, _, _, err = svc.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, active, "errors must not poison subsequent refreshes")
}

func TestStatsSnapshotWaiterCanCancel(t *testing.T) {
	svc := &IPService{statsRefresh: &statsRefresh{done: make(chan struct{})}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := svc.statsSnapshot(ctx)
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled caller waited for another request's refresh")
	}
}

func TestStatsSnapshotDoesNotCachePartialCounterFailure(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	require.NoError(t, mr.Set("stats:total_ever", "invalid-number"))
	_, _, _, _, _, _, _, _, _, _, _, err := svc.Stats(context.Background())
	require.Error(t, err)
	require.NoError(t, mr.Set("stats:total_ever", "42"))
	_, _, total, _, _, _, _, _, _, _, _, err := svc.Stats(context.Background())
	require.NoError(t, err)
	require.Equal(t, 42, total)
}
