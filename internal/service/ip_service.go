package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
)

type IPService struct {
	redisRepo     *repository.RedisRepository
	pgRepo        *repository.PostgresRepository
	blockedRanges []netip.Prefix
	geoipReader   *geoip2.Reader
	asnReader     *geoip2.Reader
}

func findGeoIPPath(filename string) string {
	paths := []string{
		filepath.Join("/home/blocklist/geoip", filename),
		filepath.Join("/home/blocklist", filename),
		filepath.Join("/usr/share/GeoIP", filename),
		filepath.Join("/tmp", filename),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func NewIPService(cfg *config.Config, rRepo *repository.RedisRepository, pgRepo *repository.PostgresRepository) *IPService {
	ranges := []netip.Prefix{}
	for _, rStr := range strings.Split(cfg.BlockedRanges, ",") {
		rStr = strings.TrimSpace(rStr)
		if rStr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(rStr)
		if err == nil {
			ranges = append(ranges, prefix)
		}
	}

	var reader, aReader *geoip2.Reader
	
	cityPath := findGeoIPPath("GeoLite2-City.mmdb")
	if cityPath != "" {
		if gReader, err := geoip2.Open(cityPath); err == nil {
			reader = gReader
		}
	}

	asnPath := findGeoIPPath("GeoLite2-ASN.mmdb")
	if asnPath != "" {
		if gaReader, err := geoip2.Open(asnPath); err == nil {
			aReader = gaReader
		}
	}

	return &IPService{
		redisRepo:     rRepo,
		pgRepo:        pgRepo,
		blockedRanges: ranges,
		geoipReader:   reader,
		asnReader:     aReader,
	}
}

func (s *IPService) IsValidIP(ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}

	// Check whitelist first
	if s.redisRepo != nil {
		whitelist, _ := s.redisRepo.GetWhitelistedIPs()
		if whitelist != nil {
			if _, ok := whitelist[ipStr]; ok {
				return false // IP is whitelisted, so it's NOT "valid to block"
			}
		}
	}

	// Check blocked ranges
	for _, prefix := range s.blockedRanges {
		if prefix.Contains(ip) {
			return false
		}
	}

	return true
}

func (s *IPService) CalculateThreatScore(ip string, reason string) int {
	if s.redisRepo == nil { return 0 }
	count, _ := s.redisRepo.GetIPBanCount(ip)
	
	// Base score: 10 points per previous ban (including this one if already incremented, 
	// but usually we call this before ExecBlockAtomic or we account for it)
	score := int(count * 10) 
	
	// Bonus points for reason severity
	reason = strings.ToLower(reason)
	if strings.Contains(reason, "brute") || strings.Contains(reason, "ssh") || strings.Contains(reason, "login") {
		score += 20
	} else if strings.Contains(reason, "sql") || strings.Contains(reason, "inject") || strings.Contains(reason, "rce") {
		score += 40
	} else if strings.Contains(reason, "spam") {
		score += 15
	} else if strings.Contains(reason, "scanner") || strings.Contains(reason, "bot") {
		score += 10
	}
	
	if score > 100 { score = 100 }
	if score < 0 { score = 0 }
	return score
}

func (s *IPService) GetGeoIP(ipStr string) *models.GeoData {
	if s.geoipReader == nil {
		// Try to reopen if it was missing on start
		cityPath := findGeoIPPath("GeoLite2-City.mmdb")
		if cityPath != "" {
			if reader, err := geoip2.Open(cityPath); err == nil {
				s.geoipReader = reader
			}
		}
	}
	if s.asnReader == nil {
		asnPath := findGeoIPPath("GeoLite2-ASN.mmdb")
		if asnPath != "" {
			if aReader, err := geoip2.Open(asnPath); err == nil {
				s.asnReader = aReader
			}
		}
	}

	ip := net.ParseIP(ipStr)
	data := &models.GeoData{}

	if s.geoipReader != nil {
		record, err := s.geoipReader.City(ip)
		if err == nil {
			data.Country = record.Country.IsoCode
			data.City = record.City.Names["en"]
			data.Latitude = record.Location.Latitude
			data.Longitude = record.Location.Longitude
		}
	}

	if s.asnReader != nil {
		asnRecord, err := s.asnReader.ASN(ip)
		if err == nil {
			data.ASN = asnRecord.AutonomousSystemNumber
			data.ASNOrg = asnRecord.AutonomousSystemOrganization
		}
	}

	if data.Country == "" && data.ASN == 0 {
		return nil
	}

	return data
}

func (s *IPService) GetTotalCount(ctx context.Context) int {
	if s.redisRepo != nil {
		if c, err := s.redisRepo.GetZSetCount(); err == nil {
			return c
		}
	}
	return 0
}

// ListIPsPaginated returns items ordered by recency with cursor-based pagination and optional query filter.
// Fallback implementation using Redis hash if sorted index is unavailable.
func (s *IPService) ListIPsPaginated(ctx context.Context, limit int, cursor string, query string) ([]map[string]interface{}, string, int, error) {
	// If ZSET exists, use score-based cursor. Otherwise fallback to hash scan.
	zs, next, zerr := s.redisRepo.ZPageByScoreDesc(limit, cursor)
	if zerr == nil && len(zs) > 0 {
		// total via GetTotalCount
		tot := s.GetTotalCount(ctx)
		items := make([]map[string]interface{}, 0, len(zs))
		q := strings.ToLower(strings.TrimSpace(query))
		for _, z := range zs {
			ip := z.Member.(string)
			entry, err := s.redisRepo.GetIPEntry(ip)
			if err != nil || entry == nil { continue }
			if q != "" {
				if !strings.Contains(strings.ToLower(ip), q) &&
					!strings.Contains(strings.ToLower(entry.Reason), q) &&
					!strings.Contains(strings.ToLower(entry.AddedBy), q) &&
					!(entry.Geolocation != nil && strings.Contains(strings.ToLower(entry.Geolocation.Country), q)) {
					continue
				}
			}
			items = append(items, map[string]interface{}{"ip": ip, "data": entry})
		}
		return items, next, tot, nil
	}
	// fallback to hash listing
	all, err := s.redisRepo.HGetAllRaw("ips")
	if err != nil { return nil, "", 0, err }
	total := len(all)
	type pair struct{ ip string; e models.IPEntry; ts int64 }
	list := make([]pair, 0, total)
	q := strings.ToLower(strings.TrimSpace(query))
	for ip, raw := range all {
		var e models.IPEntry
		if err := json.Unmarshal([]byte(raw), &e); err != nil { continue }
		if q != "" {
			if !strings.Contains(strings.ToLower(ip), q) &&
				!strings.Contains(strings.ToLower(e.Reason), q) &&
				!strings.Contains(strings.ToLower(e.AddedBy), q) &&
				!(e.Geolocation != nil && strings.Contains(strings.ToLower(e.Geolocation.Country), q)) {
				continue
			}
		}
		var ts int64
		if t, err := time.Parse("2006-01-02 15:04:05 UTC", e.Timestamp); err == nil { ts = t.Unix() }
		list = append(list, pair{ip: ip, e: e, ts: ts})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ts > list[j].ts })
	offset := 0
	if cursor != "" { if n, err := strconv.Atoi(cursor); err == nil { offset = n } }
	end := offset + limit
	if end > len(list) { end = len(list) }
	itemsOut := make([]map[string]interface{}, 0, end-offset)
	for _, p := range list[offset:end] {
		itemsOut = append(itemsOut, map[string]interface{}{"ip": p.ip, "data": p.e})
	}
	nextCursor := ""
	if end < len(list) { nextCursor = strconv.Itoa(end) }
	return itemsOut, nextCursor, len(list), nil
}

// Stats computes counts for last hour/day/total and top countries, ASNs, and reasons.
func (s *IPService) Stats(ctx context.Context) (hour int, day int, totalEver int, activeBlocks int, top []struct{ Country string; Count int }, topASN []struct{ ASN uint; ASNOrg string; Count int }, topReason []struct{ Reason string; Count int }, webhooksHour int, lastBlockTs int64, blocksMinute int, err error) {
	if s.redisRepo == nil {
		return 0, 0, 0, 0, nil, nil, nil, 0, 0, 0, nil
	}

	ips, err := s.redisRepo.GetBlockedIPs()
	if err != nil {
		return 0, 0, 0, 0, nil, nil, nil, 0, 0, 0, err
	}

	activeBlocks = len(ips)

	countryMap := make(map[string]int)
	asnMap := make(map[string]struct {
		ASN    uint
		ASNOrg string
		Count  int
	})
	reasonMap := make(map[string]int)

	for _, entry := range ips {
		if entry.Geolocation != nil {
			if entry.Geolocation.Country != "" {
				countryMap[entry.Geolocation.Country]++
			}
			if entry.Geolocation.ASN != 0 {
				key := fmt.Sprintf("%d|%s", entry.Geolocation.ASN, entry.Geolocation.ASNOrg)
				if val, ok := asnMap[key]; ok {
					val.Count++
					asnMap[key] = val
				} else {
					asnMap[key] = struct {
						ASN    uint
						ASNOrg string
						Count  int
					}{entry.Geolocation.ASN, entry.Geolocation.ASNOrg, 1}
				}
			}
		}
		if entry.Reason != "" {
			reasonMap[entry.Reason]++
		}
	}

	// Convert maps to slices and sort
	for c, count := range countryMap {
		top = append(top, struct {
			Country string
			Count   int
		}{c, count})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > 10 {
		top = top[:10]
	}

	for _, val := range asnMap {
		topASN = append(topASN, struct {
			ASN    uint
			ASNOrg string
			Count  int
		}{val.ASN, val.ASNOrg, val.Count})
	}
	sort.Slice(topASN, func(i, j int) bool { return topASN[i].Count > topASN[j].Count })
	if len(topASN) > 10 {
		topASN = topASN[:10]
	}

	for r, count := range reasonMap {
		topReason = append(topReason, struct {
			Reason string
			Count  int
		}{r, count})
	}
	sort.Slice(topReason, func(i, j int) bool { return topReason[i].Count > topReason[j].Count })
	if len(topReason) > 10 {
		topReason = topReason[:10]
	}

	h, _ := s.redisRepo.CountLastHour()
	d, _ := s.redisRepo.CountLastDay()
	totalEver, _ = s.redisRepo.CountTotalEver()
	wh, _ := s.redisRepo.CountWebhooksLastHour()
	lb, _ := s.redisRepo.GetLastBlockTime()
	bm, _ := s.redisRepo.CountBlocksLastMinute()

	return h, d, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, nil
}

// ExportIPs returns all IPs matching the filters for export purposes.
func (s *IPService) ExportIPs(ctx context.Context, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, error) {
	if s.redisRepo == nil {
		return nil, nil
	}
	// For export, we fetch a large batch or iterate.
	// Simple implementation: fetch up to 10k items.
	
	var fromTime, toTime time.Time
	if from != "" {
		fromTime, _ = time.Parse(time.RFC3339, from)
	}
	if to != "" {
		toTime, _ = time.Parse(time.RFC3339, to)
	}

	// We use ZRange to get all members if possible, or iterate in batches
	// Fetch up to 1,000,000 entries for export
	args := &redis.ZRangeArgs{
		Key:     "ips_by_ts",
		Start:   "+inf",
		Stop:    "-inf",
		ByScore: true,
		Rev:     true,
		Count:   1000000,
	}
	
	zs, err := s.redisRepo.ZRangeArgsWithScores(ctx, *args)
	// If ZSET is empty or missing, fallback to full hash scan
	if err == nil && len(zs) == 0 {
		return s.exportFallback(ctx, query, country, addedBy, fromTime, toTime)
	}
	if err != nil { return nil, err }

	items := make([]map[string]interface{}, 0)
	q := strings.ToLower(strings.TrimSpace(query))
	
	countryList := []string{}
	if country != "" {
		for _, c := range strings.Split(country, ",") {
			if trimmed := strings.TrimSpace(c); trimmed != "" {
				countryList = append(countryList, strings.ToLower(trimmed))
			}
		}
	}
	
	addedBy = strings.ToLower(strings.TrimSpace(addedBy))

	for _, z := range zs {
		ip := z.Member.(string)
		entry, err := s.redisRepo.GetIPEntry(ip)
		if err != nil || entry == nil { continue }

		if q != "" {
			if !strings.Contains(strings.ToLower(ip), q) &&
				!strings.Contains(strings.ToLower(entry.Reason), q) &&
				!strings.Contains(strings.ToLower(entry.AddedBy), q) &&
				!(entry.Geolocation != nil && strings.Contains(strings.ToLower(entry.Geolocation.Country), q)) {
				continue
			}
		}
		if len(countryList) > 0 {
			match := false
			if entry.Geolocation != nil {
				cCode := strings.ToLower(entry.Geolocation.Country)
				for _, c := range countryList {
					if cCode == c {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
		}
		if addedBy != "" {
			if !strings.EqualFold(entry.AddedBy, addedBy) {
				continue
			}
		}
		if !fromTime.IsZero() || !toTime.IsZero() {
			ts, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
			if err == nil {
				if !fromTime.IsZero() && ts.Before(fromTime) { continue }
				if !toTime.IsZero() && ts.After(toTime) { continue }
			}
		}

		items = append(items, map[string]interface{}{"ip": ip, "data": entry})
	}

	return items, nil
}

// BulkBlock blocks multiple IPs at once.
func (s *IPService) BulkBlock(ctx context.Context, ips []string, reason string, addedBy string, actorIP string, persist bool, ttl int) error {
	if s.redisRepo == nil {
		return nil
	}
	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02 15:04:05 UTC")
	
	expiresAt := ""
	if !persist {
		tVal := 86400
		if ttl > 0 { tVal = ttl }
		expiresAt = now.Add(time.Duration(tVal) * time.Second).Format("2006-01-02 15:04:05 UTC")
	}

	for _, ip := range ips {
		if !s.IsValidIP(ip) { continue }
		geo := s.GetGeoIP(ip)
		entry := models.IPEntry{
			Timestamp:   timestamp,
			Geolocation: geo,
			Reason:      reason,
			AddedBy:     fmt.Sprintf("%s (%s)", addedBy, actorIP),
			TTL:         ttl,
			ExpiresAt:   expiresAt,
			ThreatScore: s.CalculateThreatScore(ip, reason),
		}
		
		if persist && s.pgRepo != nil {
			_ = s.pgRepo.CreatePersistentBlock(ip, entry)
			_ = s.pgRepo.LogAction(addedBy, "BLOCK_PERSISTENT", ip, reason)
		} else {
			if s.pgRepo != nil {
				_ = s.pgRepo.LogAction(addedBy, "BLOCK_EPHEMERAL", ip, reason)
			}
		}
		_ = s.redisRepo.ExecBlockAtomic(ip, entry, now)
	}
	return nil
}

// BulkUnblock unblocks multiple IPs at once.
func (s *IPService) BulkUnblock(ctx context.Context, ips []string, actor string) error {
	if s.redisRepo == nil {
		return nil
	}
	for _, ip := range ips {
		_ = s.redisRepo.ExecUnblockAtomic(ip)
		if s.pgRepo != nil {
			_ = s.pgRepo.DeletePersistentBlock(ip)
			_ = s.pgRepo.LogAction(actor, "UNBLOCK", ip, "bulk action")
		}
	}
	return nil
}

// ListIPsPaginatedAdvanced provides server-side pagination and search across all records with advanced filters.
func (s *IPService) ListIPsPaginatedAdvanced(ctx context.Context, limit int, cursor string, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, string, int, error) {
	if s.redisRepo == nil {
		return nil, "", 0, nil
	}
	// Parse dates if provided
	var fromTime, toTime time.Time
	if from != "" {
		fromTime, _ = time.Parse(time.RFC3339, from)
	}
	if to != "" {
		toTime, _ = time.Parse(time.RFC3339, to)
	}

	// We'll fetch a larger batch if filtering is active to try and fulfill 'limit'
	fetchLimit := limit
	if query != "" || country != "" || addedBy != "" || from != "" || to != "" {
		fetchLimit = limit * 2 // Fetch more to account for filtering
		if fetchLimit > 5000 { fetchLimit = 5000 }
	}

	zs, next, zerr := s.redisRepo.ZPageByScoreDesc(fetchLimit, cursor)
	if zerr == nil && len(zs) > 0 {
		tot := s.GetTotalCount(ctx)
		items := make([]map[string]interface{}, 0, limit)
		q := strings.ToLower(strings.TrimSpace(query))
		
		countryList := []string{}
		if country != "" {
			for _, c := range strings.Split(country, ",") {
				if trimmed := strings.TrimSpace(c); trimmed != "" {
					countryList = append(countryList, strings.ToLower(trimmed))
				}
			}
		}
		
		addedBy = strings.ToLower(strings.TrimSpace(addedBy))

		for _, z := range zs {
			if len(items) >= limit {
				break 
			}

			ip := z.Member.(string)
			entry, err := s.redisRepo.GetIPEntry(ip)
			if err != nil || entry == nil { continue }

			// Apply filters
			if q != "" {
				if !strings.Contains(strings.ToLower(ip), q) &&
					!strings.Contains(strings.ToLower(entry.Reason), q) &&
					!strings.Contains(strings.ToLower(entry.AddedBy), q) &&
					!(entry.Geolocation != nil && strings.Contains(strings.ToLower(entry.Geolocation.Country), q)) {
					continue
				}
			}
			if len(countryList) > 0 {
				match := false
				if entry.Geolocation != nil {
					cCode := strings.ToLower(entry.Geolocation.Country)
					for _, c := range countryList {
						if cCode == c {
							match = true
							break
						}
					}
				}
				if !match {
					continue
				}
			}
			if addedBy != "" {
				if !strings.EqualFold(entry.AddedBy, addedBy) {
					continue
				}
			}
			if !fromTime.IsZero() || !toTime.IsZero() {
				ts, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
				if err == nil {
					if !fromTime.IsZero() && ts.Before(fromTime) { continue }
					if !toTime.IsZero() && ts.After(toTime) { continue }
				}
			}

			items = append(items, map[string]interface{}{"ip": ip, "data": entry})
		}
		return items, next, tot, nil
	}

	// Fallback to hash listing if ZSET is empty/failed
	return s.ListIPsPaginated(ctx, limit, cursor, query)
}

func (s *IPService) exportFallback(ctx context.Context, query string, country string, addedBy string, fromTime, toTime time.Time) ([]map[string]interface{}, error) {
	all, err := s.redisRepo.HGetAllRaw("ips")
	if err != nil { return nil, err }

	items := make([]map[string]interface{}, 0)
	q := strings.ToLower(strings.TrimSpace(query))
	countryList := []string{}
	if country != "" {
		for _, c := range strings.Split(country, ",") {
			if trimmed := strings.TrimSpace(c); trimmed != "" {
				countryList = append(countryList, strings.ToLower(trimmed))
			}
		}
	}
	addedBy = strings.ToLower(strings.TrimSpace(addedBy))

	for ip, raw := range all {
		var entry models.IPEntry
		if err := json.Unmarshal([]byte(raw), &entry); err != nil { continue }

		if q != "" {
			if !strings.Contains(strings.ToLower(ip), q) &&
				!strings.Contains(strings.ToLower(entry.Reason), q) &&
				!strings.Contains(strings.ToLower(entry.AddedBy), q) &&
				!(entry.Geolocation != nil && strings.Contains(strings.ToLower(entry.Geolocation.Country), q)) {
				continue
			}
		}
		if len(countryList) > 0 {
			match := false
			if entry.Geolocation != nil {
				cCode := strings.ToLower(entry.Geolocation.Country)
				for _, c := range countryList {
					if cCode == c {
						match = true
						break
					}
				}
			}
			if !match { continue }
		}
		if addedBy != "" {
			if !strings.EqualFold(entry.AddedBy, addedBy) { continue }
		}
		if !fromTime.IsZero() || !toTime.IsZero() {
			ts, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
			if err == nil {
				if !fromTime.IsZero() && ts.Before(fromTime) { continue }
				if !toTime.IsZero() && ts.After(toTime) { continue }
			}
		}

		items = append(items, map[string]interface{}{"ip": ip, "data": &entry})
	}
	// Sort by timestamp descending
	sort.Slice(items, func(i, j int) bool {
		ti, _ := time.Parse("2006-01-02 15:04:05 UTC", items[i]["data"].(*models.IPEntry).Timestamp)
		tj, _ := time.Parse("2006-01-02 15:04:05 UTC", items[j]["data"].(*models.IPEntry).Timestamp)
		return ti.After(tj)
	})
	return items, nil
}