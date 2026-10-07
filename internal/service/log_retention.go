package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"blocklist/internal/repository"

	zlog "github.com/rs/zerolog/log"
)

const (
	logRetentionInterval = 15 * time.Minute
	logRetentionBudget   = 30 * time.Second
	logRetentionBatches  = 100
	logRetentionPause    = 50 * time.Millisecond
)

type logBatchPruner interface {
	PruneLogBatch(context.Context, string, time.Time, int) (int64, error)
}

func (s *SchedulerService) runLogRetention() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-s.retentionContext.Done():
			return
		case <-timer.C:
			s.cleanupLogs()
			timer.Reset(logRetentionInterval)
		}
	}
}

func (s *SchedulerService) cleanupLogs() {
	// The lease outlives the two 30-second category budgets. Different replicas
	// share it; row locks additionally protect concurrent inserts/deletes.
	token, acquired, err := s.redisRepo.AcquireLock("lock_log_retention", 2*time.Minute)
	if err != nil {
		zlog.Error().Err(err).Msg("Could not acquire log retention lock")
		return
	}
	if !acquired {
		return
	}
	defer func() {
		if err := s.redisRepo.ReleaseLock("lock_log_retention", token); err != nil {
			zlog.Error().Err(err).Msg("Could not release log retention lock")
		}
	}()
	// Give both categories their own budget so an event backlog cannot starve
	// security-history cleanup. Cutoffs stay fixed for the duration of this run.
	now := time.Now().UTC()
	for _, category := range []string{"system", "events"} {
		ctx, cancel := context.WithTimeout(s.retentionContext, logRetentionBudget)
		count, err := pruneLogBatches(ctx, s.pgRepo, category, now, logRetentionPause)
		cancel()
		if errors.Is(err, context.Canceled) {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			zlog.Warn().Str("category", category).Int64("deleted", count).
				Msg("Log retention query or cycle budget reached; cleanup resumes next cycle")
		} else if err != nil {
			zlog.Error().Err(err).Str("category", category).Int64("deleted", count).
				Msg("Log retention cleanup failed; retrying next cycle")
		} else {
			zlog.Info().Str("category", category).Int64("deleted", count).
				Msg("Log retention cleanup cycle completed")
		}
	}
}

func pruneLogBatches(
	ctx context.Context,
	repo logBatchPruner,
	category string,
	now time.Time,
	pause time.Duration,
) (int64, error) {
	var total int64
	for range logRetentionBatches {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		// Bound each SQL statement as well as the whole run. No historical rows
		// are loaded into application memory and every batch commits separately.
		batchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		count, err := repo.PruneLogBatch(batchCtx, category, now, repository.MaxLogCleanupBatch)
		cancel()
		total += count
		if err != nil {
			return total, fmt.Errorf("cleaning log batch: %w", err)
		}
		if count < repository.MaxLogCleanupBatch {
			return total, nil
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return total, ctx.Err()
		case <-timer.C:
		}
	}
	return total, nil
}
