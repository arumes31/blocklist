package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bytedance/sonic"
	"math"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/metrics"
	"blocklist/internal/models"

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

// Ping checks connectivity without loading application data.
func (r *RedisRepository) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
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
		if err := sonic.UnmarshalString(v, &entry); err == nil {
			ips[k] = entry
		}
	}
	return ips, nil
}

// GetBlockedIPKeys returns the same entries as GetBlockedIPs without retaining
// their decoded metadata. Keep the single HGETALL snapshot and full IPEntry
// validation: HKEYS alone would expose records that GetBlockedIPs rejects.
func (r *RedisRepository) GetBlockedIPKeys() ([]string, error) {
	defer r.trackDuration("GetBlockedIPKeys", time.Now())
	res, err := r.HGetAllRaw("ips")
	if err != nil {
		return nil, err
	}
	return blockedIPKeys(res), nil
}

func blockedIPKeys(records map[string]string) []string {
	ips := make([]string, 0, len(records))
	var entry models.IPEntry
	for ip, data := range records {
		// Reuse the decode target, but never carry fields between records.
		entry = models.IPEntry{}
		if err := sonic.UnmarshalString(data, &entry); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (r *RedisRepository) BlockIP(ip string, entry models.IPEntry) error {
	defer r.trackDuration("BlockIP", time.Now())
	data, err := sonic.Marshal(entry)
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
	if err := sonic.UnmarshalString(val, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// GetIPEntries returns multiple IP entries from the hash in a single call.
func (r *RedisRepository) GetIPEntries(ips []string) ([]*models.IPEntry, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	defer r.trackDuration("GetIPEntries", time.Now())
	vals, err := r.client.HMGet(r.ctx, "ips", ips...).Result()
	if err != nil {
		return nil, err
	}

	entries := make([]*models.IPEntry, len(vals))
	for i, val := range vals {
		if val == nil {
			continue
		}
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		var e models.IPEntry
		if err := sonic.UnmarshalString(strVal, &e); err == nil {
			entries[i] = &e
		}
	}
	return entries, nil
}

// Index helpers for time-ordered queries
func (r *RedisRepository) IndexIPTimestamp(ip string, ts time.Time) error {
	return r.client.ZAdd(r.ctx, "ips_by_ts", redis.Z{Score: float64(ts.Unix()), Member: ip}).Err()
}

func (r *RedisRepository) RemoveIPTimestamp(ip string) error {
	return r.client.ZRem(r.ctx, "ips_by_ts", ip).Err()
}

// pageByTuple atomically finds the first tuple after the cursor in descending
// order, even if the cursor member was deleted or its timestamp changed.
// Binary search avoids scanning or downloading arbitrarily large timestamp ties.
var pageByTuple = redis.NewScript(`
local lo, hi = 0, redis.call('ZCARD', KEYS[1])
if ARGV[1] ~= '' then
    local score, member = tonumber(ARGV[1]), ARGV[2]
    while lo < hi do
        local mid = math.floor((lo + hi) / 2)
        local item = redis.call('ZREVRANGE', KEYS[1], mid, mid, 'WITHSCORES')
        local s = tonumber(item[2])
        if s > score or (s == score and item[1] >= member) then
            lo = mid + 1
        else
            hi = mid
        end
    end
end
return redis.call('ZREVRANGE', KEYS[1], lo, lo + tonumber(ARGV[3]), 'WITHSCORES')
`)

// ZPageByScoreDesc uses a score:member cursor and one-entry lookahead.
func (r *RedisRepository) ZPageByScoreDesc(limit int, cursor string) ([]redis.Z, string, error) {
	defer r.trackDuration("ZPageByScoreDesc", time.Now())
	if limit <= 0 {
		return nil, "", nil
	}
	score, member := "", ""
	if parts := strings.SplitN(cursor, ":", 2); len(parts) == 2 {
		if n, err := strconv.ParseFloat(parts[0], 64); err == nil && !math.IsNaN(n) && !math.IsInf(n, 0) {
			score, member = parts[0], parts[1]
		}
	}
	values, err := pageByTuple.Run(r.ctx, r.client, []string{"ips_by_ts"}, score, member, limit).Slice()
	if err != nil {
		return nil, "", err
	}
	res := make([]redis.Z, 0, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		n, err := strconv.ParseFloat(values[i+1].(string), 64)
		if err != nil {
			return nil, "", fmt.Errorf("decode pagination score: %w", err)
		}
		res = append(res, redis.Z{Score: n, Member: values[i].(string)})
	}

	next := ""
	if len(res) > limit {
		res = res[:limit]
		if len(res) > 0 {
			last := res[len(res)-1]
			next = fmt.Sprintf("%v:%s", last.Score, last.Member.(string))
		}
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
	if e == redis.Nil {
		return 0, nil
	}
	return v, e
}

func (r *RedisRepository) CountLastDay() (int, error) {
	now := time.Now().UTC()
	v, e := r.client.Get(r.ctx, fmt.Sprintf("stats:day:%s", now.Format("20060102"))).Int()
	if e == redis.Nil {
		return 0, nil
	}
	return v, e
}

func (r *RedisRepository) CountTotalEver() (int, error) {
	v, e := r.client.Get(r.ctx, "stats:total_ever").Int()
	if e == redis.Nil {
		return 0, nil
	}
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
		if err := sonic.UnmarshalString(v, &entry); err == nil {
			ips[k] = entry
		}
	}
	return ips, nil
}

func (r *RedisRepository) WhitelistIP(ip string, entry models.WhitelistEntry) error {
	data, err := sonic.Marshal(entry)
	if err != nil {
		return err
	}
	return r.client.HSet(r.ctx, "ips_webhook2_whitelist", ip, data).Err()
}

// WhitelistIPIfAbsent writes entry only when ip has no whitelist entry yet
// (atomic HSETNX) and reports whether it was created.
func (r *RedisRepository) WhitelistIPIfAbsent(ip string, entry models.WhitelistEntry) (bool, error) {
	data, err := sonic.Marshal(entry)
	if err != nil {
		return false, err
	}
	return r.client.HSetNX(r.ctx, "ips_webhook2_whitelist", ip, data).Result()
}

func (r *RedisRepository) RemoveFromWhitelist(ip string) error {
	return r.client.HDel(r.ctx, "ips_webhook2_whitelist", ip).Err()
}

func (r *RedisRepository) GetExcludedEntries() (map[string]models.ExcludedEntry, error) {
	res, err := r.client.HGetAll(r.ctx, "ips_webhook2_excluded").Result()
	if err != nil {
		return nil, err
	}

	entries := make(map[string]models.ExcludedEntry)
	for k, v := range res {
		var entry models.ExcludedEntry
		if err := sonic.UnmarshalString(v, &entry); err == nil {
			entries[k] = entry
		}
	}
	return entries, nil
}

func (r *RedisRepository) AddExcluded(value string, entry models.ExcludedEntry) error {
	data, err := sonic.Marshal(entry)
	if err != nil {
		return err
	}
	return r.client.HSet(r.ctx, "ips_webhook2_excluded", value, data).Err()
}

// AddExcludedIfAbsent writes entry only when value has no exclusion yet
// (atomic HSETNX) and reports whether it was created.
func (r *RedisRepository) AddExcludedIfAbsent(value string, entry models.ExcludedEntry) (bool, error) {
	data, err := sonic.Marshal(entry)
	if err != nil {
		return false, err
	}
	return r.client.HSetNX(r.ctx, "ips_webhook2_excluded", value, data).Result()
}

// upsertSystemExcludedScript writes a feed-owned exclusion unless the current
// record belongs to an operator, deciding and writing in one atomic step.
var upsertSystemExcludedScript = redis.NewScript(`
local cur = redis.call('HGET', KEYS[1], ARGV[1])
if cur then
  local ok, e = pcall(cjson.decode, cur)
  if not ok or type(e) ~= 'table' or e['added_by'] ~= 'system' then return 0 end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
return 1
`)

// UpsertSystemExcluded creates or renews a system-owned exclusion and reports
// whether it was written. Operator-owned (or unreadable) records are kept.
func (r *RedisRepository) UpsertSystemExcluded(value string, entry models.ExcludedEntry) (bool, error) {
	data, err := sonic.Marshal(entry)
	if err != nil {
		return false, err
	}
	written, err := upsertSystemExcludedScript.Run(r.ctx, r.client, []string{"ips_webhook2_excluded"}, value, string(data)).Int()
	return written == 1, err
}

// UpdateExcludedResolution stores the DNS resolution fields of resolved onto
// the current exclusion record, but only while that record still has the
// policy that was resolved. A record deleted or edited in the meantime is left
// alone and false is returned.
func (r *RedisRepository) UpdateExcludedResolution(value string, resolved models.ExcludedEntry) (bool, error) {
	const key = "ips_webhook2_excluded"
	updated := false
	err := r.client.Watch(r.ctx, func(tx *redis.Tx) error {
		raw, err := tx.HGet(r.ctx, key, value).Result()
		if errors.Is(err, redis.Nil) {
			return nil
		}
		if err != nil {
			return err
		}
		var current models.ExcludedEntry
		if err := sonic.UnmarshalString(raw, &current); err != nil {
			return nil
		}
		samePolicy := current.Timestamp == resolved.Timestamp && current.Value == resolved.Value &&
			current.Type == resolved.Type && current.AddedBy == resolved.AddedBy &&
			current.Reason == resolved.Reason && current.ExpiresAt == resolved.ExpiresAt &&
			current.AlertEnabled == resolved.AlertEnabled
		if !samePolicy {
			return nil
		}
		current.ResolvedIPs = resolved.ResolvedIPs
		current.ResolvedAt = resolved.ResolvedAt
		current.ResolveError = resolved.ResolveError
		data, err := sonic.Marshal(current)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(r.ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(r.ctx, key, value, data)
			return nil
		})
		if err == nil {
			updated = true
		}
		return err
	}, key)
	if errors.Is(err, redis.TxFailedErr) {
		// The hash changed while we compared; drop this refresh result.
		return false, nil
	}
	return updated, err
}

func (r *RedisRepository) RemoveExcluded(value string) error {
	return r.client.HDel(r.ctx, "ips_webhook2_excluded", value).Err()
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
	data, err := sonic.Marshal(val)
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
	return sonic.UnmarshalString(val, target)
}

func (r *RedisRepository) AcquireLock(key string, expiration time.Duration) (string, bool, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", false, err
	}
	token := hex.EncodeToString(b)
	err = r.client.SetArgs(r.ctx, key, token, redis.SetArgs{Mode: "NX", TTL: expiration}).Err()
	if err == redis.Nil {
		return "", false, nil
	}
	return token, err == nil, err
}

var releaseLockScript = `
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
`

func (r *RedisRepository) ReleaseLock(key string, token string) error {
	return r.client.Eval(r.ctx, releaseLockScript, []string{key}, token).Err()
}

// claimTOTPStepScript atomically accepts a TOTP time step only if it is newer
// than the last step accepted for the same account.
var claimTOTPStepScript = redis.NewScript(`
local last = tonumber(redis.call('GET', KEYS[1]) or '-1')
if tonumber(ARGV[1]) <= last then
	return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
`)

// ClaimTOTPStep records step as the last accepted TOTP time step for username.
// It returns false when the step (or a later one) was already used, so a code
// cannot be replayed within its validity window.
func (r *RedisRepository) ClaimTOTPStep(username string, step int64) (bool, error) {
	defer r.trackDuration("ClaimTOTPStep", time.Now())
	// The key outlives the +/-1 step skew window; older steps are invalid anyway.
	res, err := claimTOTPStepScript.Run(r.ctx, r.client, []string{"totp_last_step:" + username}, step, 300).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (r *RedisRepository) GetClient() *redis.Client {
	return r.client
}

// keepsLongerBlock is shared Lua that reports whether the live block for ip
// outlasts a replacement expiring at newExp (empty = permanent). expires_at uses
// the fixed "2006-01-02 15:04:05 UTC" layout, so string order is time order.
const keepsLongerBlock = `
local function keepsLongerBlock(ip, newExp)
  local existing = redis.call('HGET', 'ips', ip)
  if not existing then return false end
  local ok, cur = pcall(cjson.decode, existing)
  if not ok or type(cur) ~= 'table' then return false end
  local curExp = cur['expires_at']
  if type(curExp) ~= 'string' then curExp = '' end
  if newExp == '' then return false end
  if curExp == '' then return true end
  return curExp > newExp
end
`

// Atomic block operation: writes hash and updates ZSET in one script. A block
// never replaces one that lasts longer: shortening requires unblock rights.
var blockAtomicScript = keepsLongerBlock + `
local ip = ARGV[1]
local entry = ARGV[2]
local ts = tonumber(ARGV[3])
if keepsLongerBlock(ip, ARGV[4]) then return 0 end
redis.call('HSET','ips',ip,entry)
redis.call('ZADD','ips_by_ts',ts,ip)
return 1
`

// removeIfUnchangedScript deletes a hash field only while it still holds the
// record that was found expired (same timestamp and expiry), so a renewal
// written in between is never removed. KEYS[2], when given, is the time index.
// Returns 1 when removed, 0 when absent and -1 when the record changed.
var removeIfUnchangedScript = redis.NewScript(`
local cur = redis.call('HGET', KEYS[1], ARGV[1])
if not cur then return 0 end
local ok, e = pcall(cjson.decode, cur)
if not ok or type(e) ~= 'table' then return -1 end
local ts = e['timestamp']
if type(ts) ~= 'string' then ts = '' end
local exp = e['expires_at']
if type(exp) ~= 'string' then exp = '' end
if ts ~= ARGV[2] or exp ~= ARGV[3] then return -1 end
redis.call('HDEL', KEYS[1], ARGV[1])
if #KEYS > 1 then redis.call('ZREM', KEYS[2], ARGV[1]) end
return 1
`)

// RemoveResult reports the outcome of RemoveIfUnchanged.
type RemoveResult int

const (
	RemoveChanged RemoveResult = -1 // a different record now occupies the field
	RemoveAbsent  RemoveResult = 0
	RemoveDone    RemoveResult = 1
)

// RemoveIfUnchanged deletes field from hashKey only if it still holds a record
// with the given timestamp and expiry. Blocks are also removed from the time
// index in the same script.
func (r *RedisRepository) RemoveIfUnchanged(hashKey, field, timestamp, expiresAt string) (RemoveResult, error) {
	keys := []string{hashKey}
	if hashKey == "ips" {
		keys = append(keys, "ips_by_ts")
	}
	res, err := removeIfUnchangedScript.Run(r.ctx, r.client, keys, field, timestamp, expiresAt).Int()
	return RemoveResult(res), err
}

// Atomic unblock operation: removes from hash and ZSET in one script
var unblockAtomicScript = `
local ip = ARGV[1]
local removed = redis.call('HDEL','ips',ip)
if removed == 1 then
  redis.call('ZREM','ips_by_ts',ip)
end
return removed
`

var bulkBlockAtomicScript = keepsLongerBlock + `
local hourBucket = ARGV[1]
local dayBucket = ARGV[2]
local ts = tonumber(ARGV[3])
local newExp = ARGV[4]
local count = (#ARGV - 4) / 2

local applied = 0
for i = 1, count do
    local ip = ARGV[4 + (i-1)*2 + 1]
    local entry = ARGV[4 + (i-1)*2 + 2]
    if not keepsLongerBlock(ip, newExp) then
        redis.call('HSET', 'ips', ip, entry)
        redis.call('ZADD', 'ips_by_ts', ts, ip)
        redis.call('HINCRBY', 'ips_ban_counts', ip, 1)
        applied = applied + 1
    end
end

if applied > 0 then
    redis.call('INCRBY', hourBucket, applied)
    redis.call('INCRBY', dayBucket, applied)
    redis.call('INCRBY', 'stats:total_ever', applied)
end
return applied
`

var bulkUnblockAtomicScript = `
local count = 0
for i = 1, #ARGV do
    local ip = ARGV[i]
    local removed = redis.call('HDEL', 'ips', ip)
    if removed == 1 then
        redis.call('ZREM', 'ips_by_ts', ip)
        count = count + 1
    end
end
return count
`

// ErrBlockShortens reports that a block was not written because the existing
// block for that address lasts longer. Shortening a block requires unblocking.
var ErrBlockShortens = errors.New("an existing block for this address lasts longer")

// ExecBlockAtomic executes atomic block writes (hash, zset) and increments
// persistent counters. It returns ErrBlockShortens, writing nothing, when the
// existing block outlasts entry.
func (r *RedisRepository) ExecBlockAtomic(ip string, entry models.IPEntry, now time.Time) error {
	defer r.trackDuration("ExecBlockAtomic", time.Now())
	data, err := sonic.Marshal(entry)
	if err != nil {
		return err
	}
	applied, err := r.client.Eval(r.ctx, blockAtomicScript, []string{}, ip, string(data), fmt.Sprintf("%d", now.Unix()), entry.ExpiresAt).Int()
	if err != nil {
		return err
	}
	if applied == 0 {
		return ErrBlockShortens
	}
	// Increment persistent counters
	_ = r.IncrHourBucket(now, 1)
	_ = r.IncrDayBucket(now, 1)
	_ = r.client.HIncrBy(r.ctx, "ips_ban_counts", ip, 1)
	return nil
}

// ExecUnblockAtomic removes ip from hash and ZSET atomically; caller may adjust counters separately
func (r *RedisRepository) ExecUnblockAtomic(ip string) error {
	defer r.trackDuration("ExecUnblockAtomic", time.Now())
	_, err := r.client.Eval(r.ctx, unblockAtomicScript, []string{}, ip).Result()
	return err
}

// ExecBulkBlockAtomic executes atomic block writes for multiple IPs using a
// single Lua script. All entries share one expiry; an address whose existing
// block lasts longer is left unchanged.
func (r *RedisRepository) ExecBulkBlockAtomic(ips []string, entries []models.IPEntry, now time.Time) error {
	defer r.trackDuration("ExecBulkBlockAtomic", time.Now())
	if len(ips) != len(entries) {
		return fmt.Errorf("length mismatch: ips (%d) != entries (%d)", len(ips), len(entries))
	}
	if len(ips) == 0 {
		return nil
	}

	hourKey := fmt.Sprintf("stats:hour:%s", now.UTC().Format("2006010215"))
	dayKey := fmt.Sprintf("stats:day:%s", now.UTC().Format("20060102"))
	nowUnix := fmt.Sprintf("%d", now.Unix())

	args := make([]interface{}, 4+len(ips)*2)
	args[0] = hourKey
	args[1] = dayKey
	args[2] = nowUnix
	args[3] = entries[0].ExpiresAt

	for i, ip := range ips {
		if entries[i].ExpiresAt != entries[0].ExpiresAt {
			return fmt.Errorf("bulk block entries must share one expiry")
		}
		data, err := sonic.Marshal(entries[i])
		if err != nil {
			return err
		}
		args[4+i*2] = ip
		args[4+i*2+1] = string(data)
	}

	return r.client.Eval(r.ctx, bulkBlockAtomicScript, []string{}, args...).Err()
}

// ExecBulkUnblockAtomic executes atomic unblocks for multiple IPs using a single Lua script
func (r *RedisRepository) ExecBulkUnblockAtomic(ips []string) error {
	defer r.trackDuration("ExecBulkUnblockAtomic", time.Now())
	if len(ips) == 0 {
		return nil
	}
	args := make([]interface{}, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}
	return r.client.Eval(r.ctx, bulkUnblockAtomicScript, []string{}, args...).Err()
}

func (r *RedisRepository) GetTrueRedisCount() (int, error) {
	v, err := r.client.HLen(r.ctx, "ips").Result()
	return int(v), err
}

func (r *RedisRepository) GetZSetCount() (int, error) {
	v, err := r.client.ZCard(r.ctx, "ips_by_ts").Result()
	return int(v), err
}

func (r *RedisRepository) IncrIPBanCount(ip string) (int64, error) {
	return r.client.HIncrBy(r.ctx, "ips_ban_counts", ip, 1).Result()
}

func (r *RedisRepository) GetIPBanCount(ip string) (int64, error) {
	v, err := r.client.HGet(r.ctx, "ips_ban_counts", ip).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}

func (r *RedisRepository) GetIPBanCounts(ips []string) (map[string]int64, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	defer r.trackDuration("GetIPBanCounts", time.Now())
	vals, err := r.client.HMGet(r.ctx, "ips_ban_counts", ips...).Result()
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for i, val := range vals {
		if val == nil {
			counts[ips[i]] = 0
			continue
		}
		if strVal, ok := val.(string); ok {
			if v, err := strconv.ParseInt(strVal, 10, 64); err == nil {
				counts[ips[i]] = v
			} else {
				counts[ips[i]] = 0
			}
		} else {
			counts[ips[i]] = 0
		}
	}
	return counts, nil
}

func (r *RedisRepository) Close() error {
	return r.client.Close()
}
