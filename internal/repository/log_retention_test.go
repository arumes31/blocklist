//go:build integration

package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestLogRetentionRepository(t *testing.T) {
	if testing.Short() {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := t.Context()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("retention_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("synthetic-retention-password"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	migration, err := migrate.New("file://../../cmd/server/migrations", dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		sourceErr, databaseErr := migration.Close()
		require.NoError(t, errors.Join(sourceErr, databaseErr))
	})
	require.NoError(t, migration.Up())
	repo, err := NewPostgresRepository(dsn, dsn, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	t.Run("legacy partition retention cannot drop audit history", func(t *testing.T) {
		before, after := []string{}, []string{}
		query := "SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent = 'audit_logs'::regclass"
		require.NoError(t, repo.db.SelectContext(ctx, &before, query))
		require.NoError(t, repo.EnsurePartitions(1))
		require.NoError(t, repo.db.SelectContext(ctx, &after, query))
		require.Subset(t, after, before, "webhook policy must not drop any shared audit/event partition")
	})
	insert := func(t *testing.T, id int, at time.Time, action any, target string) {
		t.Helper()
		_, err := repo.db.ExecContext(ctx,
			`INSERT INTO audit_logs (id, timestamp, actor, action, target, reason)
			VALUES ($1, $2, 'retention-test', $3, $4, 'synthetic')`, id, at, action, target)
		require.NoError(t, err)
	}
	date := func(value string) time.Time {
		at, err := time.Parse(time.RFC3339, value)
		require.NoError(t, err)
		return at
	}

	t.Run("separate windows and composite keys", func(t *testing.T) {
		now := date("2026-10-06T12:00:00Z")
		// Ordinary monthly and DEFAULT partitions, including duplicate ids.
		insert(t, 1, date("2026-01-01T12:00:00Z"), "BLOCK", "expired-event-partition")
		insert(t, 1, date("2026-01-02T12:00:00Z"), "LOGIN_SUCCESS", "retained-audit-same-id")
		insert(t, 2, date("2026-04-01T12:00:00Z"), "UNBLOCK", "expired-event-default")
		insert(t, 3, date("2024-05-01T12:00:00Z"), "LOGIN_SUCCESS", "expired-audit-default")
		insert(t, 4, date("2025-01-01T12:00:00Z"), "CREATE_ROLE", "expired-audit-partition")
		insert(t, 5, date("2026-07-06T12:00:00Z"), "BLOCK", "event-boundary")
		insert(t, 6, date("2025-10-06T12:00:00Z"), "LOGIN_SUCCESS", "audit-boundary")
		insert(t, 7, date("2026-02-01T12:00:00Z"), nil, "retained-null-action")
		insert(t, 8, date("2025-01-05T12:00:00Z"), nil, "expired-null-action")
		insert(t, 9, date("2026-01-03T12:00:00Z"), "FUTURE_SYSTEM_ACTION", "retained-unknown-action")
		insert(t, 10, date("2025-01-06T12:00:00Z"), "FUTURE_SYSTEM_ACTION", "expired-unknown-action")
		require.NoError(t, repo.CreatePersistentBlock("198.51.100.8", models.IPEntry{
			Timestamp: "2025-01-01 12:00:00 UTC", Reason: "retention must not unblock",
		}))
		count, err := repo.PruneLogBatch(ctx, "events", now, 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, count, "batch limit is enforced")
		count, err = repo.PruneLogBatch(ctx, "events", now, 1000)
		require.NoError(t, err)
		require.EqualValues(t, 1, count)
		count, err = repo.PruneLogBatch(ctx, "system", now, 1000)
		require.NoError(t, err)
		require.EqualValues(t, 4, count)
		remaining := []string{}
		require.NoError(t, repo.db.SelectContext(ctx, &remaining, "SELECT target FROM audit_logs WHERE id < 100"))
		require.ElementsMatch(t, []string{
			"retained-audit-same-id", "event-boundary", "audit-boundary", "retained-null-action", "retained-unknown-action",
		}, remaining)
		blocks, err := repo.GetPersistentBlocks()
		require.NoError(t, err)
		require.Contains(t, blocks, "198.51.100.8")
		count, err = repo.PruneLogBatch(ctx, "system", now, 1000)
		require.NoError(t, err)
		require.Zero(t, count, "cleanup is idempotent")
	})

	t.Run("explorer count and pages exclude expired rows before cleanup", func(t *testing.T) {
		now := time.Now().UTC()
		eventCutoff, err := repo.logRetention.Cutoff("events", now)
		require.NoError(t, err)
		auditCutoff, err := repo.logRetention.Cutoff("system", now)
		require.NoError(t, err)
		insert(t, 101, eventCutoff.Add(-time.Hour), "BLOCK", "explorer")
		insert(t, 102, now.Add(-time.Minute), "BLOCK", "explorer")
		insert(t, 103, now, "UNBLOCK", "explorer")
		insert(t, 104, auditCutoff.Add(-time.Hour), "LOGIN_SUCCESS", "explorer")
		insert(t, 105, eventCutoff.Add(-time.Hour), "LOGIN_SUCCESS", "explorer")
		for _, tc := range []struct {
			name, category          string
			offset, total, rows, id int
		}{
			{"events first", "events", 0, 2, 1, 103},
			{"events second", "events", 1, 2, 1, 102},
			{"events exhausted", "events", 2, 2, 0, 0},
			{"system independent cutoff", "system", 0, 1, 1, 105},
		} {
			t.Run(tc.name, func(t *testing.T) {
				logs, total, err := repo.ListLogs(ctx, models.LogFilter{
					Category: tc.category, Actor: "retention-test", Query: "explorer", Limit: 1, Offset: tc.offset,
				})
				require.NoError(t, err)
				require.Equal(t, tc.total, total)
				require.Len(t, logs, tc.rows)
				if tc.rows > 0 {
					require.Equal(t, tc.id, logs[0].ID)
				}
			})
		}
		var count int
		require.NoError(t, repo.db.GetContext(ctx, &count, "SELECT count(*) FROM audit_logs WHERE target = 'explorer'"))
		require.Equal(t, 5, count, "listing must not delete anything")
	})

	t.Run("locked rows are skipped", func(t *testing.T) {
		at := date("2020-01-01T00:00:00Z")
		insert(t, 201, at, "BLOCK", "locked")
		tx, err := repo.db.BeginTxx(ctx, nil)
		require.NoError(t, err)
		defer rollbackIdentity(tx)
		_, err = tx.ExecContext(ctx, "SELECT id FROM audit_logs WHERE target = 'locked' FOR UPDATE")
		require.NoError(t, err)
		batchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err = repo.PruneLogBatch(batchCtx, "events", time.Now(), 1000)
		require.NoError(t, err)
		var count int
		require.NoError(t, repo.db.GetContext(ctx, &count, "SELECT count(*) FROM audit_logs WHERE target = 'locked'"))
		require.Equal(t, 1, count)
		require.NoError(t, tx.Rollback())
		_, err = repo.PruneLogBatch(ctx, "events", time.Now(), 1000)
		require.NoError(t, err)
		require.NoError(t, repo.db.GetContext(ctx, &count, "SELECT count(*) FROM audit_logs WHERE target = 'locked'"))
		require.Zero(t, count)
	})

	t.Run("rejects invalid requests and cancellation", func(t *testing.T) {
		for _, size := range []int{-1, 0, 1001} {
			_, err := repo.PruneLogBatch(ctx, "system", time.Now(), size)
			require.Error(t, err)
		}
		_, err := repo.PruneLogBatch(ctx, "unknown", time.Now(), 1)
		require.Error(t, err)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		_, err = repo.PruneLogBatch(canceled, "system", time.Now(), 1)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("shorter configured windows reach queries and cleanup", func(t *testing.T) {
		short, err := NewPostgresRepository(dsn, dsn, 0, models.LogRetention{EventMonths: 1, AuditMonths: 6})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, short.Close()) })
		now := time.Now().UTC()
		insert(t, 301, now.AddDate(0, -2, 0), "BLOCK", "shorter-window")
		insert(t, 302, now.AddDate(0, -8, 0), "LOGIN_SUCCESS", "shorter-window")
		insert(t, 303, now, "LOGIN_SUCCESS", "shorter-window")
		for _, category := range []string{"events", "system"} {
			_, total, err := short.ListLogs(ctx, models.LogFilter{Category: category, Query: "shorter-window", Limit: 50})
			require.NoError(t, err)
			want := 0
			if category == "system" {
				want = 1
			}
			require.Equal(t, want, total)
			_, err = short.PruneLogBatch(ctx, category, now, 1000)
			require.NoError(t, err)
		}
		var count int
		require.NoError(t, repo.db.GetContext(ctx, &count, "SELECT count(*) FROM audit_logs WHERE target = 'shorter-window'"))
		require.Equal(t, 1, count)
	})
}
