package repository

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"blocklist/internal/models"

	"github.com/alicebob/miniredis/v2"
	"github.com/bytedance/sonic"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRedisRepository_GetBlockedIPKeys(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := &RedisRepository{client: client, ctx: t.Context()}

	keys, err := repo.GetBlockedIPKeys()
	require.NoError(t, err)
	require.Empty(t, keys)

	records := map[string]string{
		"192.0.2.1":      `{"reason":"scanner","geolocation":{"country":"AT","latitude":48.2}}`,
		"2001:db8::1":    `{}`,
		"legacy-null":    `null`,
		"expired":        `{"expires_at":"2000-01-01 00:00:00 UTC"}`,
		"unknown-fields": `{"unknown":{"nested":true}}`,
		"broken-json":    `{`,
		"bad-ttl":        `{"ttl":"not a number"}`,
		"bad-geo":        `{"geolocation":{"latitude":"invalid"}}`,
		"bad-reason":     `{"reason":123}`,
		"array":          `[]`,
	}
	for ip, data := range records {
		mr.HSet("ips", ip, data)
	}
	full, err := repo.GetBlockedIPs()
	require.NoError(t, err)
	keys, err = repo.GetBlockedIPKeys()
	require.NoError(t, err)
	require.ElementsMatch(t, slices.Collect(maps.Keys(full)), keys)
	require.Len(t, keys, 5)
	// Reads do not lazily delete expired records or rewrite malformed data.
	stored, err := repo.HGetAllRaw("ips")
	require.NoError(t, err)
	require.Equal(t, records, stored)

	mr.SetError("ERR unavailable")
	keys, err = repo.GetBlockedIPKeys()
	require.Error(t, err)
	require.Nil(t, keys)
}

func FuzzBlockedIPKeysCompatibility(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"ttl":10}`, `{"ttl":"bad"}`, `{"geolocation":null}`, `[]`, `{`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		var entry models.IPEntry
		wantValid := sonic.UnmarshalString(data, &entry) == nil
		got := blockedIPKeys(map[string]string{"192.0.2.1": data})
		if (len(got) == 1) != wantValid {
			t.Fatalf("key-only read disagrees with full record validation")
		}
	})
}

// Compare CPU/allocation cost after the identical HGETALL snapshot. The legacy
// case intentionally mirrors GetBlockedIPs followed by the old RawIPs loop.
func BenchmarkBlockedIPKeys(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("records=%d", count), func(b *testing.B) {
			records := make(map[string]string, count)
			for i := range count {
				records[fmt.Sprintf("2001:db8::%x:%x", i/65536, i%65536)] = `{"timestamp":"2026-10-06 12:00:00 UTC","geolocation":{"country":"AT","city":"Vienna","latitude":48.2,"longitude":16.3,"asn":64496,"asn_org":"Example"},"reason":"scanner","added_by":"integration","ttl":3600,"expires_at":"2026-10-06 13:00:00 UTC","threat_score":40}`
			}
			b.Run("legacy", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					entries := make(map[string]models.IPEntry)
					for ip, data := range records {
						var entry models.IPEntry
						if sonic.UnmarshalString(data, &entry) == nil {
							entries[ip] = entry
						}
					}
					var keys []string
					for ip := range entries {
						keys = append(keys, ip)
					}
					if len(keys) != count {
						b.Fatal("missing keys")
					}
				}
			})
			b.Run("keys_only", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if len(blockedIPKeys(records)) != count {
						b.Fatal("missing keys")
					}
				}
			})
		})
	}
}
