package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"blocklist/internal/models"
	"github.com/stretchr/testify/require"
)

func TestPaginationAllResults(t *testing.T) {
	for _, indexed := range []bool{true, false} {
		t.Run(fmt.Sprintf("indexed=%t", indexed), func(t *testing.T) {
			svc, mr := setupServiceTest(t)
			defer mr.Close()
			ts := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
			for i := 0; i < 1200; i++ {
				ip := fmt.Sprintf("2001:db8::%04x", i)
				e := models.IPEntry{Timestamp: ts.Format("2006-01-02 15:04:05 UTC"), Reason: "scanner", AddedBy: "bot", Geolocation: &models.GeoData{Country: "US"}}
				if i < 200 {
					e.Reason, e.AddedBy, e.Geolocation.Country = "late needle", "operator", "AT"
				}
				require.NoError(t, svc.redisRepo.BlockIP(ip, e))
				if indexed {
					require.NoError(t, svc.redisRepo.IndexIPTimestamp(ip, ts))
				}
			}
			for _, tc := range []struct {
				name, query, country, actor string
				want                        int
			}{
				{"all", "", "", "", 1200},
				{"late_query", "needle", "", "", 200},
				{"late_filters", "", "AT", "operator", 200},
				{"combined", "needle", "AT,DE", "operator", 200},
				{"no_matches", "missing", "", "", 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					seen := map[string]bool{}
					cursor := ""
					for page := 0; ; page++ {
						require.Less(t, page, 15, "pagination must terminate")
						items, next, _, err := svc.ListIPsPaginatedAdvanced(context.Background(), 100, cursor, tc.query, tc.country, tc.actor, ts.Add(-time.Hour).Format(time.RFC3339), ts.Add(time.Hour).Format(time.RFC3339))
						require.NoError(t, err)
						require.LessOrEqual(t, len(items), 100)
						for _, item := range items {
							ip := item["ip"].(string)
							require.False(t, seen[ip], "duplicate IP %s", ip)
							seen[ip] = true
						}
						if next == "" {
							break
						}
						require.NotEmpty(t, items, "no empty trailing page")
						require.NotEqual(t, cursor, next)
						cursor = next
					}
					require.Len(t, seen, tc.want)
				})
			}
		})
	}
}

func TestPaginationExhaustedAndDeletedCursor(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	ts := time.Unix(1700000000, 0).UTC()
	for i := 0; i < 300; i++ {
		ip := fmt.Sprintf("2001:db8::%04x", i)
		require.NoError(t, svc.redisRepo.BlockIP(ip, models.IPEntry{Timestamp: ts.Format("2006-01-02 15:04:05 UTC")}))
		require.NoError(t, svc.redisRepo.IndexIPTimestamp(ip, ts))
	}
	items, cursor, _, err := svc.ListIPsPaginated(context.Background(), 100, "", "")
	require.NoError(t, err)
	require.Len(t, items, 100)
	last := items[99]["ip"].(string)
	require.NoError(t, svc.redisRepo.RemoveIPTimestamp(last))
	require.NoError(t, svc.redisRepo.HDel("ips", last))
	items, _, _, err = svc.ListIPsPaginated(context.Background(), 100, cursor, "")
	require.NoError(t, err)
	require.Len(t, items, 100)
	require.Equal(t, "2001:db8::00c7", items[0]["ip"])
	items, next, _, err := svc.ListIPsPaginated(context.Background(), 100, "1700000000:2001:db8::0000", "")
	require.NoError(t, err)
	require.Empty(t, items)
	require.Empty(t, next)
}
