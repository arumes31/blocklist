package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/stretchr/testify/require"
)

func TestInsightFilters(t *testing.T) {
	for _, indexed := range []bool{true, false} {
		t.Run(fmt.Sprintf("indexed=%t", indexed), func(t *testing.T) {
			svc, mr := setupServiceTest(t)
			t.Cleanup(mr.Close)
			ts := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
			fixtures := []struct {
				ip     string
				reason string
				actor  string
				geo    *models.GeoData
			}{
				{
					ip: "192.0.2.1", reason: "ISDB-*-Scanner", actor: "operator",
					geo: &models.GeoData{Country: "AT", ASN: 396982},
				},
				{
					ip: "192.0.2.2", reason: " \tisdb-*-scanner\n ", actor: "bot",
					geo: &models.GeoData{Country: "DE", ASN: 396982},
				},
				{
					ip: "192.0.2.3", reason: "396982 ISDB-any-Scanner", actor: "396982",
					geo: &models.GeoData{Country: "AT", ASN: 3969820},
				},
				{ip: "192.0.2.4", reason: "ISDB-*-Scanner-extra", actor: "operator"},
				{
					ip: "2001:db8::1", reason: `A:"B" & <test> / + *`, actor: "operator",
					geo: &models.GeoData{Country: "AT", ASN: 4294967295},
				},
			}
			for i, fixture := range fixtures {
				entryTime := ts.Add(time.Duration(i) * time.Minute)
				require.NoError(t, svc.redisRepo.BlockIP(fixture.ip, models.IPEntry{
					Timestamp: entryTime.Format("2006-01-02 15:04:05 UTC"),
					Reason:    fixture.reason, AddedBy: fixture.actor, Geolocation: fixture.geo,
				}))
				if indexed {
					require.NoError(t, svc.redisRepo.IndexIPTimestamp(fixture.ip, entryTime))
				}
			}

			cases := []struct {
				name    string
				query   string
				country string
				actor   string
				from    string
				to      string
				want    []string
			}{
				{name: "exact ASN", query: "asn:396982", want: []string{"192.0.2.1", "192.0.2.2"}},
				{name: "ASN case and whitespace", query: " ASN: 396982 ", want: []string{"192.0.2.1", "192.0.2.2"}},
				{name: "ASN space before colon", query: " ASN \t: 396982 ", want: []string{"192.0.2.1", "192.0.2.2"}},
				{name: "ASN leading zeros", query: "asn:00396982", want: []string{"192.0.2.1", "192.0.2.2"}},
				{name: "maximum ASN", query: "asn:4294967295", want: []string{"2001:db8::1"}},
				{name: "literal reason", query: "reason:ISDB-*-Scanner", want: []string{"192.0.2.1", "192.0.2.2"}},
				{name: "reason case and whitespace", query: " REASON \t:  ISDB-*-Scanner \n", want: []string{"192.0.2.1", "192.0.2.2"}},
				{name: "special characters", query: `reason:A:"B" & <test> / + *`, want: []string{"2001:db8::1"}},
				{
					name: "country actor dates combined", query: "asn:396982", country: "AT", actor: "operator",
					from: ts.Add(-time.Minute).Format(time.RFC3339), to: ts.Add(time.Minute).Format(time.RFC3339),
					want: []string{"192.0.2.1"},
				},
				{name: "reason and country", query: "reason:ISDB-*-Scanner", country: "DE", want: []string{"192.0.2.2"}},
				{name: "actor excludes matches", query: "asn:396982", actor: "missing"},
				{name: "date excludes matches", query: "asn:396982", from: ts.Add(time.Hour).Format(time.RFC3339)},
				{name: "empty ASN", query: "asn:"},
				{name: "invalid ASN", query: "asn:not-a-number"},
				{name: "negative ASN", query: "asn:-1"},
				{name: "overflow ASN", query: "asn:4294967296"},
				{name: "zero ASN", query: "asn:0"},
				{name: "empty reason", query: "reason:"},
				{name: "ordinary substring unchanged", query: "Scanner", want: []string{
					"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
				}},
				{name: "IPv6 unchanged", query: "2001:db8::1", want: []string{"2001:db8::1"}},
				{name: "CIDR unchanged", query: "2001:db8::/32", want: []string{"2001:db8::1"}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var got []string
					cursor := ""
					for page := 0; ; page++ {
						require.Less(t, page, 10, "filtered pagination must terminate")
						items, next, _, err := svc.ListIPsPaginatedAdvanced(
							context.Background(), 1, cursor, tc.query, tc.country, tc.actor, tc.from, tc.to,
						)
						require.NoError(t, err)
						require.LessOrEqual(t, len(items), 1)
						for _, item := range items {
							got = append(got, item["ip"].(string))
						}
						if next == "" {
							break
						}
						require.NotEqual(t, cursor, next)
						cursor = next
					}
					require.ElementsMatch(t, tc.want, got)

					exported, err := svc.ExportIPs(context.Background(), tc.query, tc.country, tc.actor, tc.from, tc.to)
					require.NoError(t, err)
					var exportedIPs []string
					for _, item := range exported {
						exportedIPs = append(exportedIPs, item["ip"].(string))
					}
					require.ElementsMatch(t, tc.want, exportedIPs, "exports and table must apply the same filters")
				})
			}
		})
	}
}

func TestInsightReasonRankings(t *testing.T) {
	t.Parallel()
	svc, mr := setupServiceTest(t)
	t.Cleanup(mr.Close)
	reasons := []string{
		" ISDB-*-Scanner ", "isdb-*-scanner", "\tISDB-*-Scanner\n",
		"ISDB-*-Scanner-extra", `A:"B" & <test> / + *`, ` a:"b" & <TEST> / + * `,
		" Trim Me ", "", " \t\n",
	}
	for i, reason := range reasons {
		require.NoError(t, svc.redisRepo.BlockIP(fmt.Sprintf("192.0.2.%d", i+1), models.IPEntry{Reason: reason}))
	}
	_, _, _, active, _, _, ranked, _, _, _, _, err := svc.Stats(t.Context())
	require.NoError(t, err)
	require.Equal(t, len(reasons), active)
	want := map[string]int{
		"ISDB-*-Scanner": 3, "ISDB-*-Scanner-extra": 1, `A:"B" & <test> / + *`: 2, "Trim Me": 1,
	}
	got := make(map[string]int)
	for _, rank := range ranked {
		got[rank.Reason] = rank.Count
		exported, exportErr := svc.ExportIPs(
			t.Context(),
			"reason:"+rank.Reason,
			"",
			"",
			"",
			"",
		)
		require.NoError(t, exportErr)
		require.Len(t, exported, rank.Count, "a chip's count must equal its exact-filter results")
	}
	require.Len(t, ranked, len(want), "case/whitespace variants share one chip; blank reasons have no chip")
	require.Equal(t, want, got, "keep stable, original-cased labels")
	stored, err := svc.redisRepo.GetBlockedIPs()
	require.NoError(t, err)
	for i, reason := range reasons {
		require.Equal(t, reason, stored[fmt.Sprintf("192.0.2.%d", i+1)].Reason, "do not rewrite stored reasons")
	}

	for _, tc := range []struct {
		name  string
		query string
	}{
		{name: "internal spacing", query: `reason:A: "B" & <test> / + *`},
		{name: "reason prefix", query: "reason:ISDB-*-Scan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exported, err := svc.ExportIPs(
				t.Context(),
				tc.query,
				"",
				"",
				"",
				"",
			)
			require.NoError(t, err)
			require.Empty(t, exported, "preserve internal spacing and exact, non-substring matching")
		})
	}
}
