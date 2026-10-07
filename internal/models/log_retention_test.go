package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLogRetentionCutoff(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, now, want, category string
		months                    int
	}{
		{"three months", "2026-10-06T15:04:05Z", "2026-07-06T15:04:05Z", "events", 3},
		{"month end", "2026-03-31T15:04:05Z", "2026-02-28T15:04:05Z", "events", 1},
		{"leap year", "2024-05-31T15:04:05Z", "2024-02-29T15:04:05Z", "events", 3},
		{"year boundary", "2026-01-31T15:04:05Z", "2025-11-30T15:04:05Z", "events", 2},
		{"utc boundary", "2026-04-01T00:30:00+02:00", "2026-02-28T22:30:00Z", "events", 1},
		{"one year", "2026-10-06T15:04:05Z", "2025-10-06T15:04:05Z", "system", 12},
		{"leap day last year", "2024-02-29T15:04:05Z", "2023-02-28T15:04:05Z", "system", 12},
		{"six months", "2026-08-31T15:04:05Z", "2026-02-28T15:04:05Z", "system", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now, err := time.Parse(time.RFC3339, tc.now)
			require.NoError(t, err)
			policy := DefaultLogRetention()
			if tc.category == "events" {
				policy.EventMonths = tc.months
			} else {
				policy.AuditMonths = tc.months
			}
			cutoff, err := policy.Cutoff(tc.category, now)
			require.NoError(t, err)
			require.Equal(t, tc.want, cutoff.Format(time.RFC3339))
		})
	}
}

func TestLogRetentionRejectsInvalidMonths(t *testing.T) {
	t.Parallel()
	for _, policy := range []LogRetention{{-1, 12}, {0, 12}, {4, 12}, {3, 0}, {3, -1}, {3, 13}} {
		_, err := policy.Cutoff("system", time.Now())
		require.Error(t, err)
	}
	_, err := DefaultLogRetention().Cutoff("unknown", time.Now())
	require.Error(t, err)
}
