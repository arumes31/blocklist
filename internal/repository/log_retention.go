package repository

import (
	"context"
	"fmt"
	"time"

	"blocklist/internal/models"
)

// MaxLogCleanupBatch bounds the number of row locks held by each cleanup query.
const MaxLogCleanupBatch = 1000

// PruneLogBatch deletes expired rows only, including rows in the DEFAULT
// partition. The two log categories never share a cutoff or a partition drop.
func (p *PostgresRepository) PruneLogBatch(
	ctx context.Context,
	category string,
	now time.Time,
	batchSize int,
) (int64, error) {
	if batchSize < 1 || batchSize > MaxLogCleanupBatch {
		return 0, fmt.Errorf("log cleanup batch size must be between 1 and %d", MaxLogCleanupBatch)
	}
	cutoff, err := p.logRetention.Cutoff(category, now)
	if err != nil {
		return 0, fmt.Errorf("resolving log cleanup retention: %w", err)
	}
	// Order matches the existing (id, timestamp) primary key. The age/action
	// predicate can still scan retained rows; callers must bound query time.
	// SKIP LOCKED avoids waiting on active writers.
	// Both key columns are essential: ids alone are not unique across partitions.
	result, err := p.db.ExecContext(ctx, `
		WITH expired AS (
			SELECT id, timestamp FROM audit_logs
			WHERE timestamp < $1 AND COALESCE(action = ANY($2::text[]), FALSE) = $3
			ORDER BY id, timestamp LIMIT $4 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM audit_logs AS logs USING expired
		WHERE logs.id = expired.id AND logs.timestamp = expired.timestamp`,
		cutoff, models.EventActions, category == "events", batchSize,
	)
	if err != nil {
		return 0, fmt.Errorf("pruning %s logs: %w", category, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("counting pruned %s logs: %w", category, err)
	}
	return count, nil
}
