package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/metrics"
	"github.com/redis/go-redis/v9"
)

type RedisRepository struct {
	client *redis.Client
	ctx    context.Context
}

func (r *RedisRepository) trackDuration(op string, start time.Time) {
	metrics.MetricRedisDuration.WithLabelValues(op).Observe(time.Since(start).Seconds())
}

func NewRedisRepository(host string, port int, db int) *RedisRepository {
	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", host, port),
		DB:   db,
	})
	return &RedisRepository{
		client: rdb,
		ctx:    context.Background(),
	}
}

func (r *RedisRepository) HGetAllRaw(hashKey string) (map[string]string, error) {
	defer r.trackDuration("HGetAllRaw", time.Now())
	return r.client.HGetAll(r.ctx, hashKey).Result()
}

func (r *RedisRepository) HDel(hashKey, field string) error {
	defer r.trackDuration("HDel", time.Now())
	return r.client.HDel(r.ctx, hashKey, field).Err()
}

func (r *RedisRepository) GetBlockedIPs() (map[string]models.IPEntry, error) {
	defer r.trackDuration("GetBlockedIPs", time.Now())
	res, err := r.HGetAllRaw("ips")
	if err != nil {
		return nil, err
	}

	ips := make(map[string]models.IPEntry)
	for k, v := range res {
		var entry models.IPEntry
		if err := json.Unmarshal([]byte(v), &entry); err == nil {
			ips[k] = entry
		}
	}
	return ips, nil
}

func (r *RedisRepository) BlockIP(ip string, entry models.IPEntry) error {
	defer r.trackDuration("BlockIP", time.Now())
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return r.client.HSet(r.ctx, "ips", ip, data).Err()
}

// GetIPEntry returns a single IP entry from the hash.
func (r *RedisRepository) GetIPEntry(ip string) (*models.IPEntry, error) {
	defer r.trackDuration("GetIPEntry", time.Now())
	val, err := r.client.HGet(r.ctx, "ips", ip).Result()
	if err != nil {
		return nil, err
	}
	var e models.IPEntry
	if err := json.Unmarshal([]byte(val), &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Index helpers for time-ordered queries
func (r *RedisRepository) IndexIPTimestamp(ip string, ts time.Time) error {
	return r.client.ZAdd(r.ctx, "ips_by_ts", redis.Z{Score: float64(ts.Unix()), Member: ip}).Err()
}

func (r *RedisRepository) RemoveIPTimestamp(ip string) error {
	return r.client.ZRem(r.ctx, "ips_by_ts", ip).Err()
}

// ZPageByScoreDesc paginates ips_by_ts using a stable tuple cursor (score:member).
// Cursor format: "<score>:<member>". Empty cursor starts from +inf.
func (r *RedisRepository) ZPageByScoreDesc(limit int, cursor string) ([]redis.Z, string, error) {
	defer r.trackDuration("ZPageByScoreDesc", time.Now())
	
	start := "+inf"
	var lastMember string
	if cursor != "" {
		parts := strings.SplitN(cursor, ":", 2)
		start = "(" + parts[0]
		if len(parts) > 1 {
			lastMember = parts[1]
		}
	}

	args := &redis.ZRangeArgs{
		Key:     "ips_by_ts",
		Start:   start,
		Stop:    "-inf",
		ByScore: true,
		Rev:     true,
		Count:   int64(limit + 50), // Fetch slightly more to handle member-level offset
	}
	
	res, err := r.client.ZRangeArgsWithScores(r.ctx, *args).Result()
	if err != nil { return nil, "", err }

	// If we have a lastMember, we need to filter out items until we find it
	if lastMember != "" {
		found := false
		for i, z := range res {
			if z.Member.(string) == lastMember {
				res = res[i+1:]
				found = true
				break
			}
		}
		if !found {
			// If not found, it might have been unblocked. 
			// We just continue from the score.
		}
	}

	if len(res) > limit {
		res = res[:limit]
	}

	next := ""
	if len(res) > 0 {
		last := res[len(res)-1]
		next = fmt.Sprintf("%v:%s", last.Score, last.Member.(string))
	}
	return res, next, nil
}

// Stats counters
func (r *RedisRepository) IncrTotal(delta int64) error {
	return r.client.IncrBy(r.ctx, "stats:total", delta).Err()
}

func (r *RedisRepository) GetTotal() (int, error) {
	v, err := r.client.Get(r.ctx, "stats:total").Int()
	if err == redis.Nil { return 0, nil }
	return v, err
}

func (r *RedisRepository) IncrCountry(country string, delta int64) error {
	if country == "" { return nil }
	return r.client.HIncrBy(r.ctx, "stats:country", country, delta).Err()
}

func (r *RedisRepository) TopCountries(limit int) ([]struct{ Country string; Count int }, error) {
	res, err := r.client.HGetAll(r.ctx, "stats:country").Result()
	if err != nil { return nil, err }
	arr := make([]struct{ Country string; Count int }, 0, len(res))
	for k, v := range res {
		iv, _ := strconv.Atoi(v)
		arr = append(arr, struct{ Country string; Count int }{k, iv})
	}
	sort.Slice(arr, func(i,j int) bool { return arr[i].Count > arr[j].Count })
	if limit > 0 && len(arr) > limit { arr = arr[:limit] }
	return arr, nil
}

func (r *RedisRepository) IncrASN(asn uint, asnOrg string, delta int64) error {
	if asn == 0 { return nil }
	key := fmt.Sprintf("%d|%s", asn, asnOrg)
	return r.client.HIncrBy(r.ctx, "stats:asn", key, delta).Err()
}

func (r *RedisRepository) TopASNs(limit int) ([]struct{ ASN uint; ASNOrg string; Count int }, error) {
	res, err := r.client.HGetAll(r.ctx, "stats:asn").Result()
	if err != nil { return nil, err }
	arr := make([]struct{ ASN uint; ASNOrg string; Count int }, 0, len(res))
	for k, v := range res {
		parts := strings.SplitN(k, "|", 2)
		asn, _ := strconv.Atoi(parts[0])
		org := ""
		if len(parts) > 1 { org = parts[1] }
		iv, _ := strconv.Atoi(v)
		arr = append(arr, struct{ ASN uint; ASNOrg string; Count int }{uint(asn), org, iv})
	}
	sort.Slice(arr, func(i,j int) bool { return arr[i].Count > arr[j].Count })
	if limit > 0 && len(arr) > limit { arr = arr[:limit] }
	return arr, nil
}

func (r *RedisRepository) IncrReason(reason string, delta int64) error {
	if reason == "" { return nil }
	return r.client.HIncrBy(r.ctx, "stats:reason", reason, delta).Err()
}

func (r *RedisRepository) TopReasons(limit int) ([]struct{ Reason string; Count int }, error) {
	res, err := r.client.HGetAll(r.ctx, "stats:reason").Result()
	if err != nil { return nil, err }
	arr := make([]struct{ Reason string; Count int }, 0, len(res))
	for k, v := range res {
		iv, _ := strconv.Atoi(v)
		arr = append(arr, struct{ Reason string; Count int }{k, iv})
	}
	sort.Slice(arr, func(i,j int) bool { return arr[i].Count > arr[j].Count })
	if limit > 0 && len(arr) > limit { arr = arr[:limit] }
	return arr, nil
}

// Time-bucketed counters (hour/day)
func (r *RedisRepository) IncrHourBucket(ts time.Time, delta int64) error {
	key := fmt.Sprintf("stats:hour:%s", ts.UTC().Format("2006010215"))
	return r.client.IncrBy(r.ctx, key, delta).Err()
}
func (r *RedisRepository) IncrDayBucket(ts time.Time, delta int64) error {
	key := fmt.Sprintf("stats:day:%s", ts.UTC().Format("20060102"))
	return r.client.IncrBy(r.ctx, key, delta).Err()
}

func (r *RedisRepository) CountLastHour() (int, error) {
	// Prefer ZSET if present
	now := time.Now().UTC()
	min := float64(now.Add(-1*time.Hour).Unix())
	max := float64(now.Unix())
	cnt, err := r.client.ZCount(r.ctx, "ips_by_ts", fmt.Sprintf("%f", min), fmt.Sprintf("%f", max)).Result()
	if err == nil { return int(cnt), nil }
	// Fallback to bucket key
	v, e := r.client.Get(r.ctx, fmt.Sprintf("stats:hour:%s", now.Format("2006010215"))).Int()
	if e == redis.Nil { return 0, nil }
	return v, e
}

func (r *RedisRepository) CountLastDay() (int, error) {
	now := time.Now().UTC()
	min := float64(now.Add(-24*time.Hour).Unix())
	max := float64(now.Unix())
	cnt, err := r.client.ZCount(r.ctx, "ips_by_ts", fmt.Sprintf("%f", min), fmt.Sprintf("%f", max)).Result()
	if err == nil { return int(cnt), nil }
	v, e := r.client.Get(r.ctx, fmt.Sprintf("stats:day:%s", now.Format("20060102"))).Int()
	if e == redis.Nil { return 0, nil }
	return v, e
}

func (r *RedisRepository) UnblockIP(ip string) error {
	return r.client.HDel(r.ctx, "ips", ip).Err()
}

func (r *RedisRepository) GetWhitelistedIPs() (map[string]models.WhitelistEntry, error) {
	res, err := r.client.HGetAll(r.ctx, "ips_webhook2_whitelist").Result()
	if err != nil {
		return nil, err
	}

	ips := make(map[string]models.WhitelistEntry)
	for k, v := range res {
		var entry models.WhitelistEntry
		if err := json.Unmarshal([]byte(v), &entry); err == nil {
			ips[k] = entry
		}
	}
	return ips, nil
}

func (r *RedisRepository) WhitelistIP(ip string, entry models.WhitelistEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return r.client.HSet(r.ctx, "ips_webhook2_whitelist", ip, data).Err()
}

func (r *RedisRepository) RemoveFromWhitelist(ip string) error {
	return r.client.HDel(r.ctx, "ips_webhook2_whitelist", ip).Err()
}

func (r *RedisRepository) SetCache(key string, val interface{}, expiration time.Duration) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return r.client.Set(r.ctx, key, data, expiration).Err()
}

func (r *RedisRepository) GetCache(key string, target interface{}) error {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), target)
}

func (r *RedisRepository) AcquireLock(key string, expiration time.Duration) (bool, error) {
	return r.client.SetNX(r.ctx, key, "lock", expiration).Result()
}

func (r *RedisRepository) ReleaseLock(key string) error {
	return r.client.Del(r.ctx, key).Err()
}

// Atomic block operation: writes hash, updates ZSET, and increments counters in one script
var blockAtomicScript = `
local ip = ARGV[1]
local entry = ARGV[2]
local ts = tonumber(ARGV[3])
local country = ARGV[4]
local hourKey = ARGV[5]
local dayKey = ARGV[6]
local reason = ARGV[7]
local asnKey = ARGV[8]
redis.call('HSET','ips',ip,entry)
redis.call('ZADD','ips_by_ts',ts,ip)
redis.call('INCR','stats:total')
if country ~= nil and country ~= '' then
  redis.call('HINCRBY','stats:country', country, 1)
end
if reason ~= nil and reason ~= '' then
  redis.call('HINCRBY','stats:reason', reason, 1)
end
if asnKey ~= nil and asnKey ~= '' then
  redis.call('HINCRBY','stats:asn', asnKey, 1)
end
redis.call('INCR',hourKey)
redis.call('INCR',dayKey)
return 1
`

// Atomic unblock operation: removes from hash and ZSET in one script
var unblockAtomicScript = `
local ip = ARGV[1]
redis.call('HDEL','ips',ip)
redis.call('ZREM','ips_by_ts',ip)
return 1
`

// ExecBlockAtomic executes atomic block writes (hash, zset, counters)
func (r *RedisRepository) ExecBlockAtomic(ip string, entry models.IPEntry, now time.Time) error {
	defer r.trackDuration("ExecBlockAtomic", time.Now())
	data, err := json.Marshal(entry)
	if err != nil { return err }
	country := ""
	asnKey := ""
	if entry.Geolocation != nil {
		country = entry.Geolocation.Country
		if entry.Geolocation.ASN != 0 {
			asnKey = fmt.Sprintf("%d|%s", entry.Geolocation.ASN, entry.Geolocation.ASNOrg)
		}
	}
	hourKey := fmt.Sprintf("stats:hour:%s", now.UTC().Format("2006010215"))
	dayKey := fmt.Sprintf("stats:day:%s", now.UTC().Format("20060102"))
	_, err = r.client.Eval(r.ctx, blockAtomicScript, []string{}, ip, string(data), fmt.Sprintf("%d", now.Unix()), country, hourKey, dayKey, entry.Reason, asnKey).Result()
	return err
}

// ExecUnblockAtomic removes ip from hash and ZSET atomically; caller may adjust counters separately
func (r *RedisRepository) ExecUnblockAtomic(ip string) error {
	defer r.trackDuration("ExecUnblockAtomic", time.Now())
	_, err := r.client.Eval(r.ctx, unblockAtomicScript, []string{}, ip).Result()
	return err
}
