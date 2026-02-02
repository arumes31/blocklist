package repository

import (
	"context"
	"encoding/json"
	"fmt"
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

func NewRedisRepository(host string, port int, password string, db int) *RedisRepository {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password,
		DB:       db,
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
	
	max := "+inf"
	var lastMember string
	if cursor != "" {
		parts := strings.SplitN(cursor, ":", 2)
		max = parts[0]
		if len(parts) > 1 {
			lastMember = parts[1]
		}
	}

	opt := &redis.ZRangeBy{
		Min:    "-inf",
		Max:    max,
		Offset: 0,
		Count:  int64(limit + 50),
	}
	
	res, err := r.client.ZRevRangeByScoreWithScores(r.ctx, "ips_by_ts", opt).Result()
	if err != nil { return nil, "", err }

	// If we have a lastMember, we need to filter out items until we find it
	if lastMember != "" {
		for i, z := range res {
			if z.Member.(string) == lastMember {
				res = res[i+1:]
				break
			}
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

// ZRangeArgsWithScores fetches range from ZSET
func (r *RedisRepository) ZRangeArgsWithScores(ctx context.Context, args redis.ZRangeArgs) ([]redis.Z, error) {
	defer r.trackDuration("ZRangeArgsWithScores", time.Now())
	return r.client.ZRangeArgsWithScores(ctx, args).Result()
}

// Time-bucketed counters (hour/day) - these remain useful for trending
func (r *RedisRepository) IncrHourBucket(ts time.Time, delta int64) error {
	key := fmt.Sprintf("stats:hour:%s", ts.UTC().Format("2006010215"))
	_ = r.client.IncrBy(r.ctx, "stats:total_ever", delta) // Also increment global total
	return r.client.IncrBy(r.ctx, key, delta).Err()
}
func (r *RedisRepository) IncrDayBucket(ts time.Time, delta int64) error {
	key := fmt.Sprintf("stats:day:%s", ts.UTC().Format("20060102"))
	return r.client.IncrBy(r.ctx, key, delta).Err()
}

func (r *RedisRepository) CountLastHour() (int, error) {
	now := time.Now().UTC()
	v, e := r.client.Get(r.ctx, fmt.Sprintf("stats:hour:%s", now.Format("2006010215"))).Int()
	if e == redis.Nil { return 0, nil }
	return v, e
}

func (r *RedisRepository) CountLastDay() (int, error) {
	now := time.Now().UTC()
	v, e := r.client.Get(r.ctx, fmt.Sprintf("stats:day:%s", now.Format("20060102"))).Int()
	if e == redis.Nil { return 0, nil }
	return v, e
}

func (r *RedisRepository) CountTotalEver() (int, error) {
	v, e := r.client.Get(r.ctx, "stats:total_ever").Int()
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

func (r *RedisRepository) IndexWebhookHit(ts time.Time) error {
	return r.client.ZAdd(r.ctx, "webhooks_by_ts", redis.Z{Score: float64(ts.Unix()), Member: fmt.Sprintf("%d-%d", ts.UnixNano(), ts.Unix())}).Err()
}

func (r *RedisRepository) CountWebhooksLastHour() (int, error) {
	now := time.Now().UTC()
	min := float64(now.Add(-1 * time.Hour).Unix())
	max := float64(now.Unix())
	cnt, err := r.client.ZCount(r.ctx, "webhooks_by_ts", fmt.Sprintf("%f", min), fmt.Sprintf("%f", max)).Result()
	if err != nil {
		return 0, err
	}
	// Cleanup old entries while we're at it (older than 24h)
	_ = r.client.ZRemRangeByScore(r.ctx, "webhooks_by_ts", "-inf", fmt.Sprintf("%f", float64(now.Add(-24*time.Hour).Unix())))
	return int(cnt), nil
}

func (r *RedisRepository) GetLastBlockTime() (int64, error) {
	res, err := r.client.ZRevRangeWithScores(r.ctx, "ips_by_ts", 0, 0).Result()
	if err != nil || len(res) == 0 {
		return 0, err
	}
	return int64(res[0].Score), nil
}

func (r *RedisRepository) CountBlocksLastMinute() (int, error) {
	now := time.Now().UTC()
	min := float64(now.Add(-1 * time.Minute).Unix())
	max := float64(now.Unix())
	cnt, err := r.client.ZCount(r.ctx, "ips_by_ts", fmt.Sprintf("%f", min), fmt.Sprintf("%f", max)).Result()
	if err != nil {
		return 0, err
	}
	return int(cnt), nil
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

func (r *RedisRepository) GetClient() *redis.Client {
	return r.client
}

// Atomic block operation: writes hash and updates ZSET in one script
var blockAtomicScript = `
local ip = ARGV[1]
local entry = ARGV[2]
local ts = tonumber(ARGV[3])
redis.call('HSET','ips',ip,entry)
redis.call('ZADD','ips_by_ts',ts,ip)
return 1
`

// Atomic unblock operation: removes from hash and ZSET in one script
var unblockAtomicScript = `
local ip = ARGV[1]
local removed = redis.call('HDEL','ips',ip)
if removed == 1 then
  redis.call('ZREM','ips_by_ts',ip)
end
return removed
`

// ExecBlockAtomic executes atomic block writes (hash, zset) and increments persistent counters
func (r *RedisRepository) ExecBlockAtomic(ip string, entry models.IPEntry, now time.Time) error {
	defer r.trackDuration("ExecBlockAtomic", time.Now())
	data, err := json.Marshal(entry)
	if err != nil { return err }
	_, err = r.client.Eval(r.ctx, blockAtomicScript, []string{}, ip, string(data), fmt.Sprintf("%d", now.Unix())).Result()
	if err == nil {
		// Increment persistent counters
		_ = r.IncrHourBucket(now, 1)
		_ = r.IncrDayBucket(now, 1)
	}
	return err
}

// ExecUnblockAtomic removes ip from hash and ZSET atomically; caller may adjust counters separately
func (r *RedisRepository) ExecUnblockAtomic(ip string) error {
	defer r.trackDuration("ExecUnblockAtomic", time.Now())
	_, err := r.client.Eval(r.ctx, unblockAtomicScript, []string{}, ip).Result()
	return err
}

func (r *RedisRepository) GetTrueRedisCount() (int, error) {
	v, err := r.client.HLen(r.ctx, "ips").Result()
	return int(v), err
}

func (r *RedisRepository) GetZSetCount() (int, error) {
	v, err := r.client.ZCard(r.ctx, "ips_by_ts").Result()
	return int(v), err
}
