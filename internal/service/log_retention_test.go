package service

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"blocklist/internal/repository"

	"github.com/stretchr/testify/require"
)

type retentionPrunerFunc func(context.Context, string, time.Time, int) (int64, error)

func (f retentionPrunerFunc) PruneLogBatch(ctx context.Context, category string, now time.Time, batch int) (int64, error) {
	return f(ctx, category, now, batch)
}

func TestPruneLogBatches(t *testing.T) {
	t.Parallel()
	failure := errors.New("database unavailable")
	for _, tc := range []struct {
		name  string
		rows  []int64
		err   error
		calls int
		total int64
	}{
		{name: "empty", rows: []int64{0}, calls: 1},
		{name: "partial batch", rows: []int64{17}, calls: 1, total: 17},
		{name: "multiple batches", rows: []int64{1000, 1000, 12}, calls: 3, total: 2012},
		{name: "row budget", rows: []int64{1000}, calls: logRetentionBatches, total: 100000},
		{name: "stops on failure", rows: []int64{0}, err: failure, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			now := time.Now()
			fake := retentionPrunerFunc(func(ctx context.Context, category string, at time.Time, batch int) (int64, error) {
				require.Equal(t, "system", category)
				require.Equal(t, now, at)
				require.Equal(t, repository.MaxLogCleanupBatch, batch)
				_, bounded := ctx.Deadline()
				require.True(t, bounded)
				rows := tc.rows[min(calls, len(tc.rows)-1)]
				calls++
				return rows, tc.err
			})
			total, err := pruneLogBatches(t.Context(), fake, "system", now, 0)
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.calls, calls)
			require.Equal(t, tc.total, total)
		})
	}
}

func TestPruneLogBatchesCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		calls := 0
		fake := retentionPrunerFunc(func(ctx context.Context, _ string, _ time.Time, _ int) (int64, error) {
			calls++
			cancel()
			return 1000, nil
		})
		total, err := pruneLogBatches(ctx, fake, "events", time.Now(), time.Hour)
		require.ErrorIs(t, err, context.Canceled)
		require.EqualValues(t, 1000, total)
		require.Equal(t, 1, calls)
	})
}

func TestPruneLogBatchesQueryTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := retentionPrunerFunc(func(ctx context.Context, _ string, _ time.Time, _ int) (int64, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		})
		started := time.Now()
		_, err := pruneLogBatches(t.Context(), fake, "system", started, 0)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 5*time.Second, time.Since(started))
	})
}

func TestSchedulerStopCancelsLogRetention(t *testing.T) {
	scheduler := NewSchedulerService(nil, nil, nil)
	scheduler.Stop()
	scheduler.Stop()
	require.ErrorIs(t, scheduler.retentionContext.Err(), context.Canceled)
}
