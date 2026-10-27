package service

import (
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/stretchr/testify/require"
)

func TestIPServiceShowsEntraAccountsBySignInName(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	svc.SetAccountLabels(NewAccountLabels(&fakeAccountLabelSource{labels: map[string]string{
		testEntraKey: "editor@example.test",
	}}))
	now := time.Now().UTC()
	for i, entry := range []struct{ ip, addedBy string }{
		{ip: "198.51.100.1", addedBy: testEntraKey + " (203.0.113.7)"},
		{ip: "198.51.100.2", addedBy: testEntraKey},
		{ip: "198.51.100.3", addedBy: "operator (203.0.113.8)"},
	} {
		ts := now.Add(time.Duration(-i) * time.Minute)
		require.NoError(t, svc.redisRepo.BlockIP(entry.ip, models.IPEntry{
			Timestamp: ts.Format("2006-01-02 15:04:05 UTC"), Reason: "scanner", AddedBy: entry.addedBy,
		}))
		require.NoError(t, svc.redisRepo.IndexIPTimestamp(entry.ip, ts))
	}
	shown := func(t *testing.T, items []map[string]interface{}) map[string]string {
		t.Helper()
		byIP := map[string]string{}
		for _, item := range items {
			byIP[item["ip"].(string)] = item["data"].(*models.IPEntry).AddedBy
		}
		return byIP
	}

	t.Run("list", func(t *testing.T) {
		items, _, _, err := svc.ListIPsPaginatedAdvanced(t.Context(), 10, "", "", "", "", "", "")
		require.NoError(t, err)
		require.Equal(t, map[string]string{
			"198.51.100.1": "editor@example.test (203.0.113.7)",
			"198.51.100.2": "editor@example.test",
			"198.51.100.3": "operator (203.0.113.8)",
		}, shown(t, items))
	})
	t.Run("search and Added By accept the sign-in name or stored key", func(t *testing.T) {
		for _, tc := range []struct{ query, addedBy string }{
			{query: "EDITOR@example"},
			{query: "26854b10"},
			{addedBy: "Editor@Example.test"},
			{addedBy: testEntraKey},
		} {
			items, _, _, err := svc.ListIPsPaginatedAdvanced(t.Context(), 10, "", tc.query, "", tc.addedBy, "", "")
			require.NoError(t, err)
			want := 2
			if tc.addedBy != "" {
				want = 1 // Added By stays an exact match; blocks include the actor address.
			}
			require.Len(t, items, want, "query=%q added_by=%q", tc.query, tc.addedBy)
			for _, addedBy := range shown(t, items) {
				require.NotContains(t, addedBy, "entra:")
			}
		}
	})
	t.Run("export", func(t *testing.T) {
		items, err := svc.ExportIPs(t.Context(), "", "", "", "", "")
		require.NoError(t, err)
		require.Equal(t, "editor@example.test (203.0.113.7)", shown(t, items)["198.51.100.1"])
	})
	t.Run("details", func(t *testing.T) {
		details, err := svc.GetIPDetails(t.Context(), "198.51.100.1")
		require.NoError(t, err)
		require.Equal(t, "editor@example.test (203.0.113.7)", details["current"].(*models.IPEntry).AddedBy)
	})
	t.Run("stored records keep the account key", func(t *testing.T) {
		entry, err := svc.redisRepo.GetIPEntry("198.51.100.2")
		require.NoError(t, err)
		require.Equal(t, testEntraKey, entry.AddedBy)
	})
}

func TestIPServiceHashFallbackShowsSignInName(t *testing.T) {
	svc, mr := setupServiceTest(t)
	defer mr.Close()
	svc.SetAccountLabels(NewAccountLabels(&fakeAccountLabelSource{labels: map[string]string{
		testEntraKey: "editor@example.test",
	}}))
	require.NoError(t, svc.redisRepo.BlockIP("198.51.100.9", models.IPEntry{
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"), AddedBy: testEntraKey + " (203.0.113.7)",
	}))
	items, _, _, err := svc.ListIPsPaginatedAdvanced(t.Context(), 10, "", "", "", "", "", "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "editor@example.test (203.0.113.7)", items[0]["data"].(models.IPEntry).AddedBy)
}
