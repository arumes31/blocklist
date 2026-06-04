package service

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
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
	"sync"
	"sync/atomic"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
	zlog "github.com/rs/zerolog/log"
)

const MaxPageSize = 1000

type IPService struct {
	redisRepo      *repository.RedisRepository
	pgRepo         *repository.PostgresRepository
	webhookService *WebhookService
	mailService    *MailService
	blockedRanges  []netip.Prefix
	geoipReader    *geoip2.Reader
	asnReader      *geoip2.Reader
	bloomFilter    *bloom.BloomFilter
	bloomMu        sync.RWMutex
	syncInProgress atomic.Bool
	fqdnCache      map[string]fqdnResolution
	fqdnCacheMu    sync.Mutex
	ptrCache       map[netip.Addr]ptrResolution
	ptrCacheMu     sync.Mutex
}

// fqdnResolution caches the set of addresses an excluded FQDN currently resolves
// to, so that block-time exclusion checks do not hit DNS on every call.
type fqdnResolution struct {
	addrs   map[netip.Addr]struct{}
	expires time.Time
}

// ptrResolution caches the reverse-DNS (PTR) names for an address, used for
// wildcard FQDN exclusion matching.
type ptrResolution struct {
	names   []string
	expires time.Time
}

const (
	// fqdnCacheTTL is how long a successful FQDN resolution is cached.
	fqdnCacheTTL = 5 * time.Minute
	// fqdnCacheNegTTL is how long a failed/empty resolution is cached, to avoid
	// hammering DNS for a host that does not resolve.
	fqdnCacheNegTTL = 1 * time.Minute
)

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

	gaPath := findGeoIPPath("GeoLite2-ASN.mmdb")
	if gaPath != "" {
		if gaReader, err := geoip2.Open(gaPath); err == nil {
			aReader = gaReader
		}
	}

	svc := &IPService{
		redisRepo:     rRepo,
		pgRepo:        pgRepo,
		blockedRanges: ranges,
		geoipReader:   reader,
		asnReader:     aReader,
		bloomFilter:   bloom.NewWithEstimates(1000000, 0.01),
		fqdnCache:     make(map[string]fqdnResolution),
		ptrCache:      make(map[netip.Addr]ptrResolution),
	}
	svc.syncBloomFilter()
	return svc
}

func (s *IPService) SetWebhookService(wh *WebhookService) {
	s.webhookService = wh
}

func (s *IPService) SetMailService(ms *MailService) {
	s.mailService = ms
}

func (s *IPService) triggerExcludedAlert(ctx context.Context, ip string, reason string, addedBy string, actorIP string, entry models.ExcludedEntry) {
	// 1. Webhook Alert
	if s.webhookService != nil {
		payload := map[string]interface{}{
			"event":          "excluded_block_attempt",
			"target_ip":      ip,
			"attempted_by":   addedBy,
			"actor_ip":       actorIP,
			"attempt_reason": reason,
			"excluded_rule":  entry.Value,
			"rule_type":      entry.Type,
			"rule_reason":    entry.Reason,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(payload)
		s.webhookService.Notify(ctx, "excluded_block_attempt", string(data))
	}

	// 2. Email Alert
	if s.mailService != nil {
		// Sanitize untrusted fields for email-safe text output:
		//  1) strip CR/LF (sanitizeHeader) to prevent header-style injection
		//     primitives, while the literal "\n" line breaks in the template stay
		//     intact so the email remains multi-line.
		//  2) HTML-escape so any markup/script-like payload is neutralized if the
		//     message is rendered by a downstream client/parser.
		safeIP := html.EscapeString(sanitizeHeader(ip))
		safeAddedBy := html.EscapeString(sanitizeHeader(addedBy))
		safeActorIP := html.EscapeString(sanitizeHeader(actorIP))
		safeReason := html.EscapeString(sanitizeHeader(reason))
		safeEntryValue := html.EscapeString(sanitizeHeader(entry.Value))
		safeEntryType := html.EscapeString(sanitizeHeader(entry.Type))
		safeEntryReason := html.EscapeString(sanitizeHeader(entry.Reason))

		subject := fmt.Sprintf("[ALERT] Block Attempted on Excluded Resource: %s", safeIP)
		body := fmt.Sprintf("A block was attempted but prevented for an excluded resource.\n\n"+
			"Target IP: %s\n"+
			"Attempted By: %s\n"+
			"Actor IP: %s\n"+
			"Attempt Reason: %s\n\n"+
			"Exclusion Rule: %s (%s)\n"+
			"Rule Reason: %s\n"+
			"Timestamp: %s\n",
			safeIP, safeAddedBy, safeActorIP, safeReason,
			safeEntryValue, safeEntryType, safeEntryReason,
			time.Now().UTC().Format(time.RFC3339))
		_ = s.mailService.SendAlert(subject, body)
	}
}
func (s *IPService) syncBloomFilter() {
	if !s.syncInProgress.CompareAndSwap(false, true) {
		return // A sync is already concurrently running
	}
	defer s.syncInProgress.Store(false)

	s.bloomMu.Lock()
	defer s.bloomMu.Unlock()

	// Re-initialize if too many false positives expected?
	// For now, just fill from Redis
	if s.redisRepo != nil {
		ips, err := s.redisRepo.GetBlockedIPs()
		if err != nil {
			zlog.Error().Err(err).Msg("IPService: Failed to fetch blocked IPs for Bloom Filter sync")
			return
		}
		for ip := range ips {
			s.bloomFilter.AddString(ip)
		}
		zlog.Info().Int("count", len(ips)).Msg("IPService: Synchronized Bloom Filter")
	}
}

func (s *IPService) IsBlocked(ipStr string) bool {
	// 1. Check Bloom Filter (fast positive check)
	s.bloomMu.RLock()
	if s.bloomFilter != nil && !s.bloomFilter.TestString(ipStr) {
		s.bloomMu.RUnlock()
		return false // Definitely not blocked
	}
	s.bloomMu.RUnlock()

	// 2. Fallback to Redis for confirmation
	if s.redisRepo != nil {
		entry, err := s.redisRepo.GetIPEntry(ipStr)
		if err == nil && entry != nil {
			if entry.ExpiresAt != "" {
				exp, err := time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
				if err == nil && time.Now().UTC().After(exp) {
					// Entry expired, remove it and treat as not blocked
					_ = s.redisRepo.UnblockIP(ipStr)
					return false
				}
			}
			return true
		}
	}
	return false
}

func (s *IPService) ReloadReaders() {
	cityPath := findGeoIPPath("GeoLite2-City.mmdb")
	if cityPath != "" {
		if reader, err := geoip2.Open(cityPath); err == nil {
			old := s.geoipReader
			s.geoipReader = reader
			if old != nil {
				_ = old.Close()
			}
			zlog.Info().Msg("IPService: Reloaded GeoLite2-City")
		}
	}

	asnPath := findGeoIPPath("GeoLite2-ASN.mmdb")
	if asnPath != "" {
		if aReader, err := geoip2.Open(asnPath); err == nil {
			old := s.asnReader
			s.asnReader = aReader
			if old != nil {
				_ = old.Close()
			}
			zlog.Info().Msg("IPService: Reloaded GeoLite2-ASN")
		}
	}
}

func (s *IPService) isValidIPInternal(ipStr string, ip netip.Addr, whitelist map[string]models.WhitelistEntry, excluded map[string]models.ExcludedEntry) (bool, *models.ExcludedEntry) {
	if whitelist != nil {
		if entry, ok := whitelist[ipStr]; ok {
			if entry.ExpiresAt != "" {
				exp, err := time.Parse(time.RFC3339, entry.ExpiresAt)
				if err == nil && time.Now().After(exp) {
					_ = s.redisRepo.RemoveFromWhitelist(ipStr)
				} else {
					return false, nil
				}
			} else {
				return false, nil
			}
		}
	}

	// Excluded list: IPs, subnets, or FQDNs that must never be blocked.
	if entry := s.isExcludedMatch(ip, excluded); entry != nil {
		return false, entry
	}

	for _, prefix := range s.blockedRanges {
		if prefix.Contains(ip) {
			return false, nil
		}
	}

	return true, nil
}

func (s *IPService) IsValidIP(ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}

	var whitelist map[string]models.WhitelistEntry
	var excluded map[string]models.ExcludedEntry
	if s.redisRepo != nil {
		whitelist, _ = s.redisRepo.GetWhitelistedIPs()
		excluded, _ = s.redisRepo.GetExcludedEntries()
	}

	valid, _ := s.isValidIPInternal(ipStr, ip, whitelist, excluded)
	return valid
}

// classifyExclusionType infers whether an excluded value is a wildcard FQDN, a
// CIDR, a single IP, or a plain FQDN.
func classifyExclusionType(value string) string {
	if strings.HasPrefix(value, "*.") {
		return "wildcard"
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return "cidr"
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "ip"
	}
	return "fqdn"
}

// excludedExpired reports whether an excluded entry has passed its expiry,
// lazily removing it from storage when so. ExpiresAt is parsed leniently,
// accepting both RFC3339 and the "2006-01-02 15:04:05 UTC" layout used elsewhere
// for timestamps. An empty or unparseable ExpiresAt is treated as not-expired:
// for an exclusion (never-block) list, over-protecting is the safe direction.
func (s *IPService) excludedExpired(value string, entry models.ExcludedEntry) bool {
	if entry.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, entry.ExpiresAt)
	if err != nil {
		exp, err = time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
	}
	if err != nil {
		return false
	}
	if time.Now().After(exp) {
		if s.redisRepo != nil {
			_ = s.redisRepo.RemoveExcluded(value)
		}
		return true
	}
	return false
}

// isExcludedMatch reports which entry on the excluded list matched the given
// IP, if any. Expired entries are lazily removed as they are encountered.
func (s *IPService) isExcludedMatch(ip netip.Addr, excluded map[string]models.ExcludedEntry) *models.ExcludedEntry {
	if len(excluded) == 0 {
		return nil
	}
	ip = ip.Unmap()
	ipStr := ip.String()

	// Fast path: an exact IP key is the common case and avoids a full scan.
	if entry, ok := excluded[ipStr]; ok && !s.excludedExpired(ipStr, entry) {
		e := entry // copy
		return &e
	}

	for value, entry := range excluded {
		if value == ipStr {
			continue // exact key already handled by the fast path above
		}
		if s.excludedExpired(value, entry) {
			continue
		}

		typ := entry.Type
		if typ == "" {
			typ = classifyExclusionType(value)
		}

		matched := false
		switch typ {
		case "fqdn":
			if _, ok := s.resolveFQDN(value)[ip]; ok {
				matched = true
			}
		case "wildcard":
			if s.matchWildcard(value, ip) {
				matched = true
			}
		case "cidr":
			if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(ip) {
				matched = true
			}
		default: // "ip"
			if addr, err := netip.ParseAddr(value); err == nil && addr.Unmap() == ip {
				matched = true
			}
		}

		if matched {
			e := entry // copy
			return &e
		}
	}
	return nil
}

// matchWildcard reports whether ip belongs to a wildcard FQDN exclusion such as
// "*.example.com". It uses forward-confirmed reverse DNS (FCrDNS): the address
// is reverse-resolved to candidate names, and a candidate is only accepted if it
// matches the wildcard suffix AND forward-resolves back to the same address.
// The forward confirmation prevents an attacker from evading a block by setting
// a spoofed PTR record on an IP they control.
func (s *IPService) matchWildcard(pattern string, ip netip.Addr) bool {
	base := strings.ToLower(strings.TrimPrefix(pattern, "*."))
	if base == "" {
		return false
	}
	suffix := "." + base
	for _, name := range s.lookupPTR(ip) {
		if name != base && !strings.HasSuffix(name, suffix) {
			continue
		}
		if _, ok := s.resolveFQDN(name)[ip]; ok {
			return true
		}
	}
	return false
}

// resolveAndCache resolves host to its current address set, stores it in the
// FQDN cache, and returns the set along with any resolution error.
func (s *IPService) resolveAndCache(host string) (map[netip.Addr]struct{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)

	addrs := make(map[netip.Addr]struct{}, len(ips))
	for _, a := range ips {
		addrs[a.Unmap()] = struct{}{}
	}
	ttl := fqdnCacheTTL
	if err != nil || len(addrs) == 0 {
		ttl = fqdnCacheNegTTL
	}

	s.fqdnCacheMu.Lock()
	s.fqdnCache[host] = fqdnResolution{addrs: addrs, expires: time.Now().Add(ttl)}
	s.fqdnCacheMu.Unlock()
	return addrs, err
}

// resolveFQDN returns the set of addresses host currently resolves to, using a
// short-lived cache so block-time exclusion checks do not hit DNS on every call.
func (s *IPService) resolveFQDN(host string) map[netip.Addr]struct{} {
	s.fqdnCacheMu.Lock()
	if cached, ok := s.fqdnCache[host]; ok && time.Now().Before(cached.expires) {
		addrs := cached.addrs
		s.fqdnCacheMu.Unlock()
		return addrs
	}
	s.fqdnCacheMu.Unlock()

	addrs, _ := s.resolveAndCache(host)
	return addrs
}

// lookupPTR returns the lower-cased reverse-DNS names for ip, using a cache.
func (s *IPService) lookupPTR(ip netip.Addr) []string {
	s.ptrCacheMu.Lock()
	if cached, ok := s.ptrCache[ip]; ok && time.Now().Before(cached.expires) {
		names := cached.names
		s.ptrCacheMu.Unlock()
		return names
	}
	s.ptrCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := net.DefaultResolver.LookupAddr(ctx, ip.String())

	names := make([]string, 0, len(raw))
	for _, n := range raw {
		names = append(names, strings.ToLower(strings.TrimSuffix(n, ".")))
	}
	ttl := fqdnCacheTTL
	if err != nil || len(names) == 0 {
		ttl = fqdnCacheNegTTL
	}

	s.ptrCacheMu.Lock()
	s.ptrCache[ip] = ptrResolution{names: names, expires: time.Now().Add(ttl)}
	s.ptrCacheMu.Unlock()
	return names
}

// IsExcluded reports whether the given IP is on the excluded list and therefore
// must never be blocked.
func (s *IPService) IsExcluded(ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	var excluded map[string]models.ExcludedEntry
	if s.redisRepo != nil {
		excluded, _ = s.redisRepo.GetExcludedEntries()
	}
	return s.isExcludedMatch(ip, excluded) != nil
}

// GetExcludedCount returns the number of entries on the excluded list.
func (s *IPService) GetExcludedCount(ctx context.Context) int {
	if s.redisRepo == nil {
		return 0
	}
	entries, err := s.redisRepo.GetExcludedEntries()
	if err != nil {
		return 0
	}
	return len(entries)
}

// ExclusionConflicts returns human-readable warnings about a value being added
// to the excluded list: whether it is currently blocked, already present, or
// already covered by an existing excluded subnet or a configured blocked range.
func (s *IPService) ExclusionConflicts(ctx context.Context, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || s.redisRepo == nil {
		return nil
	}
	var warns []string
	typ := classifyExclusionType(value)

	existing, _ := s.redisRepo.GetExcludedEntries()
	if _, ok := existing[value]; ok {
		warns = append(warns, fmt.Sprintf("%s is already on the excluded list; it will be updated.", value))
	}

	switch typ {
	case "ip":
		if addr, err := netip.ParseAddr(value); err == nil {
			addr = addr.Unmap()
			// Currently blocked?
			if entry, err := s.redisRepo.GetIPEntry(value); err == nil && entry != nil {
				warns = append(warns, fmt.Sprintf("%s is currently blocked; excluding it does not remove the existing block — unblock it separately.", value))
			}
			// Inside configured blocked range?
			for _, prefix := range s.blockedRanges {
				if prefix.Contains(addr) {
					warns = append(warns, fmt.Sprintf("%s falls within configured blocked range %s.", value, prefix.String()))
				}
			}
			// Covered by existing excluded subnet?
			for ev, ee := range existing {
				if (ee.Type == "cidr" || (ee.Type == "" && classifyExclusionType(ev) == "cidr")) && ev != value {
					if p, perr := netip.ParsePrefix(ev); perr == nil && p.Contains(addr) {
						warns = append(warns, fmt.Sprintf("%s is already covered by excluded subnet %s.", value, ev))
					}
				}
			}
		}
	case "cidr":
		if prefix, err := netip.ParsePrefix(value); err == nil {
			prefix = prefix.Masked()
			// Check if any blocked IPs are inside this subnet
			blocked, _ := s.redisRepo.GetBlockedIPs()
			count := 0
			for ipStr := range blocked {
				if ip, ierr := netip.ParseAddr(ipStr); ierr == nil && prefix.Contains(ip.Unmap()) {
					count++
				}
			}
			if count > 0 {
				warns = append(warns, fmt.Sprintf("%s covers %d currently blocked IPs; they will NOT be automatically unblocked.", value, count))
			}
		}
	case "fqdn":
		// Resolve now to see if it's currently blocked
		addrs, _ := s.resolveAndCache(value)
		blockedCount := 0
		blockedIPs := []string{}
		for a := range addrs {
			if s.IsBlocked(a.String()) {
				blockedCount++
				blockedIPs = append(blockedIPs, a.String())
			}
		}
		if blockedCount > 0 {
			warns = append(warns, fmt.Sprintf("%s currently resolves to blocked IPs: %s. Exclusion will not remove these existing blocks.", value, strings.Join(blockedIPs, ", ")))
		}
	}

	return warns
}

// RefreshExcludedFQDNs re-resolves every FQDN entry on the excluded list,
// warming the in-memory cache and persisting the resolved addresses (or the
// failure) back onto each entry. Resolution failures are logged as warnings.
func (s *IPService) RefreshExcludedFQDNs(ctx context.Context) {
	if s.redisRepo == nil {
		return
	}
	entries, err := s.redisRepo.GetExcludedEntries()
	if err != nil {
		zlog.Error().Err(err).Msg("excluded: failed to load entries for FQDN refresh")
		return
	}

	now := time.Now().UTC()
	for value, entry := range entries {
		typ := entry.Type
		if typ == "" {
			typ = classifyExclusionType(value)
		}
		if typ != "fqdn" {
			continue
		}
		if entry.ExpiresAt != "" {
			if exp, perr := time.Parse(time.RFC3339, entry.ExpiresAt); perr == nil && now.After(exp) {
				continue // expired; the scheduler cleanup will remove it
			} else if perr != nil {
				if exp, perr = time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt); perr == nil && now.After(exp) {
					continue
				}
			}
		}

		addrs, rerr := s.resolveAndCache(value)
		entry.ResolvedAt = now.Format("2006-01-02 15:04:05 UTC")
		if rerr != nil || len(addrs) == 0 {
			msg := "no addresses resolved"
			if rerr != nil {
				msg = rerr.Error()
			}
			entry.ResolveError = msg
			// Do NOT clear ResolvedIPs on failure; keep the last known good set
			// to provide best-effort protection during DNS outages.
			zlog.Warn().Str("fqdn", value).Str("error", msg).Msg("excluded: FQDN resolution failed")
		} else {
			entry.ResolveError = ""
			ips := make([]string, 0, len(addrs))
			for a := range addrs {
				ips = append(ips, a.String())
			}
			sort.Strings(ips)
			entry.ResolvedIPs = ips
		}

		if err := s.redisRepo.AddExcluded(value, entry); err != nil {
			zlog.Error().Err(err).Str("fqdn", value).Msg("excluded: failed to persist resolution result")
		}
	}
}

// CalculateThreatScore computes a risk score (0-100) for an IP based on its history and current reason.
func (s *IPService) calculateThreatScoreInternal(banCount int64, normalizedReason string) int {
	score := int(banCount * 10)

	if strings.Contains(normalizedReason, "brute") || strings.Contains(normalizedReason, "ssh") || strings.Contains(normalizedReason, "login") {
		score += 20
	} else if strings.Contains(normalizedReason, "sql") || strings.Contains(normalizedReason, "inject") || strings.Contains(normalizedReason, "rce") {
		score += 40
	} else if strings.Contains(normalizedReason, "spam") {
		score += 15
	} else if strings.Contains(normalizedReason, "scanner") || strings.Contains(normalizedReason, "bot") {
		score += 10
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (s *IPService) CalculateThreatScore(ip string, reason string) int {
	if s.redisRepo == nil {
		return 0
	}
	count, _ := s.redisRepo.GetIPBanCount(ip)
	return s.calculateThreatScoreInternal(count, strings.ToLower(reason))
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
	if limit <= 0 {
		limit = MaxPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	q := strings.ToLower(strings.TrimSpace(query))

	fetchLimit := limit
	if q != "" {
		fetchLimit = 500
	}

	// If ZSET exists, use score-based cursor. Otherwise fallback to hash scan.
	zs, next, zerr := s.redisRepo.ZPageByScoreDesc(fetchLimit, cursor)
	if zerr == nil && len(zs) > 0 {
		// total via GetTotalCount
		tot := s.GetTotalCount(ctx)
		// Use the fixed MaxPageSize constant for capacity instead of the
		// user-derived limit (already clamped to <= MaxPageSize above). This keeps
		// any untrusted value out of make()'s size argument so CodeQL's allocation
		// taint analysis (CWE-770) is satisfied; capacity is only a growth hint.
		items := make([]map[string]interface{}, 0, MaxPageSize)

		var currentCursor string
		for {
			ips := make([]string, len(zs))
			for i, z := range zs {
				ips[i] = z.Member.(string)
			}
			entries, err := s.redisRepo.GetIPEntries(ips)
			if err != nil {
				return items, currentCursor, tot, err
			}

			var lastAddedCursor string
			for i, z := range zs {
				if len(items) >= limit {
					break
				}
				ip := ips[i]
				entry := entries[i]
				if entry == nil {
					continue
				}
				if q != "" {
					if !strings.Contains(strings.ToLower(ip), q) &&
						!strings.Contains(strings.ToLower(entry.Reason), q) &&
						!strings.Contains(strings.ToLower(entry.AddedBy), q) &&
						(entry.Geolocation == nil || !strings.Contains(strings.ToLower(entry.Geolocation.Country), q)) {
						continue
					}
				}
				items = append(items, map[string]interface{}{"ip": ip, "data": entry})
				lastAddedCursor = fmt.Sprintf("%v:%s", z.Score, z.Member.(string))
			}

			if len(items) >= limit {
				if lastAddedCursor != "" {
					currentCursor = lastAddedCursor
				} else {
					currentCursor = next
				}
				break
			}
			currentCursor = next
			if currentCursor == "" {
				break
			}

			// Fetch next page
			zs, next, zerr = s.redisRepo.ZPageByScoreDesc(fetchLimit, currentCursor)
			if zerr != nil {
				return items, currentCursor, tot, zerr
			}
			if len(zs) == 0 {
				break
			}
		}
		return items, currentCursor, tot, nil
	}
	// fallback to hash listing
	all, err := s.redisRepo.HGetAllRaw("ips")
	if err != nil {
		return nil, "", 0, err
	}
	total := len(all)
	type pair struct {
		ip string
		e  models.IPEntry
		ts int64
	}
	list := make([]pair, 0, total)
	for ip, raw := range all {
		var e models.IPEntry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			continue
		}
		if q != "" {
			if !strings.Contains(strings.ToLower(ip), q) &&
				!strings.Contains(strings.ToLower(e.Reason), q) &&
				!strings.Contains(strings.ToLower(e.AddedBy), q) &&
				(e.Geolocation == nil || !strings.Contains(strings.ToLower(e.Geolocation.Country), q)) {
				continue
			}
		}
		var ts int64
		if t, err := time.Parse("2006-01-02 15:04:05 UTC", e.Timestamp); err == nil {
			ts = t.Unix()
		}
		list = append(list, pair{ip: ip, e: e, ts: ts})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ts > list[j].ts })
	offset := 0
	if cursor != "" {
		if n, err := strconv.Atoi(cursor); err == nil && n > 0 {
			offset = n
		}
	}
	// Clamp offset into range so a crafted cursor cannot produce a negative
	// slice bound or a negative make() capacity (both panic -> DoS).
	if offset > len(list) {
		offset = len(list)
	}
	end := offset + limit
	if end > len(list) {
		end = len(list)
	}
	itemsOut := make([]map[string]interface{}, 0, end-offset)
	for _, p := range list[offset:end] {
		itemsOut = append(itemsOut, map[string]interface{}{"ip": p.ip, "data": p.e})
	}
	nextCursor := ""
	if end < len(list) {
		nextCursor = strconv.Itoa(end)
	}
	return itemsOut, nextCursor, len(list), nil
}

// Stats computes counts for last hour/day/total and top countries, ASNs, and reasons.
func (s *IPService) Stats(ctx context.Context) (hour int, day int, totalEver int, activeBlocks int, top []struct {
	Country string
	Count   int
}, topASN []struct {
	ASN    uint
	ASNOrg string
	Count  int
}, topReason []struct {
	Reason string
	Count  int
}, webhooksHour int, lastBlockTs int64, blocksMinute int, whitelistCount int, err error) {
	if s.redisRepo == nil {
		return 0, 0, 0, 0, nil, nil, nil, 0, 0, 0, 0, nil
	}

	ips, err := s.redisRepo.GetBlockedIPs()
	if err != nil {
		return 0, 0, 0, 0, nil, nil, nil, 0, 0, 0, 0, err
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

	wips, _ := s.redisRepo.GetWhitelistedIPs()
	whitelistCount = len(wips)

	return h, d, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, whitelistCount, nil
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
	if err != nil {
		return nil, err
	}

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

	// Optimize CIDR parsing
	var queryNetwork *net.IPNet
	if q != "" {
		if _, network, err := net.ParseCIDR(query); err == nil {
			queryNetwork = network
		}
	}

	// Batch fetch entries in groups of 100 to avoid N+1 queries
	batchSize := 100
	for i := 0; i < len(zs); i += batchSize {
		end := i + batchSize
		if end > len(zs) {
			end = len(zs)
		}
		batchZs := zs[i:end]
		ips := make([]string, len(batchZs))
		for j, z := range batchZs {
			ips[j] = z.Member.(string)
		}

		entries, err := s.redisRepo.GetIPEntries(ips)
		if err != nil {
			zlog.Error().Err(err).Int("batch_start", i).Msg("ExportIPs: failed to fetch batch of IP entries")
			return nil, err
		}

		for j, entry := range entries {
			if !s.matchesFilters(ips[j], entry, q, queryNetwork, countryList, addedBy, fromTime, toTime) {
				continue
			}

			// Ensure we always store a pointer to IPEntry
			items = append(items, map[string]interface{}{"ip": ips[j], "data": entry})
		}
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
		if ttl > 0 {
			tVal = ttl
		}
		expiresAt = now.Add(time.Duration(tVal) * time.Second).Format("2006-01-02 15:04:05 UTC")
	}

	// Deduplicate input IPs
	uniqueIPs := make([]string, 0, len(ips))
	seen := make(map[string]struct{})
	for _, ip := range ips {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	// Batch fetch data
	whitelist, _ := s.redisRepo.GetWhitelistedIPs()
	excluded, _ := s.redisRepo.GetExcludedEntries()
	banCounts, _ := s.redisRepo.GetIPBanCounts(uniqueIPs)
	normalizedReason := strings.ToLower(reason)

	validIPs := make([]string, 0, len(uniqueIPs))
	validEntries := make([]models.IPEntry, 0, len(uniqueIPs))

	for _, ipStr := range uniqueIPs {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		valid, matchedEntry := s.isValidIPInternal(ipStr, addr, whitelist, excluded)
		if !valid {
			if matchedEntry != nil && matchedEntry.AlertEnabled {
				go s.triggerExcludedAlert(ctx, ipStr, reason, addedBy, actorIP, *matchedEntry)
			}
			continue
		}

		geo := s.GetGeoIP(ipStr)
		banCount := int64(0)
		if banCounts != nil {
			banCount = banCounts[ipStr]
		}

		entry := models.IPEntry{
			Timestamp:   timestamp,
			Geolocation: geo,
			Reason:      reason,
			AddedBy:     fmt.Sprintf("%s (%s)", addedBy, actorIP),
			TTL:         ttl,
			ExpiresAt:   expiresAt,
			ThreatScore: s.calculateThreatScoreInternal(banCount, normalizedReason),
		}
		validIPs = append(validIPs, ipStr)
		validEntries = append(validEntries, entry)
	}

	if len(validIPs) == 0 {
		return nil
	}

	if persist && s.pgRepo != nil {
		_ = s.pgRepo.BulkCreatePersistentBlocks(validIPs, validEntries)
		_ = s.pgRepo.BulkLogAction(addedBy, "BLOCK_PERSISTENT", validIPs, reason)
	} else if s.pgRepo != nil {
		_ = s.pgRepo.BulkLogAction(addedBy, "BLOCK_EPHEMERAL", validIPs, reason)
	}
	err := s.redisRepo.ExecBulkBlockAtomic(validIPs, validEntries, now)
	if err == nil {
		s.bloomMu.Lock()
		if s.bloomFilter != nil {
			for _, ip := range validIPs {
				s.bloomFilter.AddString(ip)
			}
		}
		s.bloomMu.Unlock()
	}
	return err
}

// BulkUnblock unblocks multiple IPs at once.
func (s *IPService) BulkUnblock(ctx context.Context, ips []string, actor string) error {
	if s.redisRepo == nil || len(ips) == 0 {
		return nil
	}

	err := s.redisRepo.ExecBulkUnblockAtomic(ips)
	if err != nil {
		return err
	}

	if s.pgRepo != nil {
		_ = s.pgRepo.BulkDeletePersistentBlocks(ips)
		_ = s.pgRepo.BulkLogAction(actor, "UNBLOCK", ips, "bulk action")
	}

	// Full re-sync is needed for Bloom filter because it doesn't support removals
	go s.syncBloomFilter()
	return nil
}

func (s *IPService) matchesFilters(ip string, entry *models.IPEntry, q string, queryNetwork *net.IPNet, countryList []string, addedBy string, fromTime, toTime time.Time) bool {
	if entry == nil {
		return false
	}

	// 1. Query filter (text match and CIDR)
	if q != "" {
		matches := false
		// Text match on fields
		if strings.Contains(strings.ToLower(ip), q) ||
			strings.Contains(strings.ToLower(entry.Reason), q) ||
			strings.Contains(strings.ToLower(entry.AddedBy), q) ||
			(entry.Geolocation != nil && strings.Contains(strings.ToLower(entry.Geolocation.Country), q)) {
			matches = true
		}

		// Smart Match: CIDR
		if !matches && queryNetwork != nil {
			if parsedIP := net.ParseIP(ip); parsedIP != nil && queryNetwork.Contains(parsedIP) {
				matches = true
			}
		}

		if !matches {
			return false
		}
	}

	// 2. Country filter
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
			return false
		}
	}

	// 3. AddedBy filter
	if addedBy != "" {
		if !strings.EqualFold(entry.AddedBy, addedBy) {
			return false
		}
	}

	// 4. Date range filters
	if !fromTime.IsZero() || !toTime.IsZero() {
		ts, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
		if err == nil {
			if !fromTime.IsZero() && ts.Before(fromTime) {
				return false
			}
			if !toTime.IsZero() && ts.After(toTime) {
				return false
			}
		}
	}

	return true
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
	if limit <= 0 {
		limit = MaxPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	fetchLimit := limit
	if query != "" || country != "" || addedBy != "" || from != "" || to != "" {
		fetchLimit = 500 // Fetch in chunks
	}

	zs, next, zerr := s.redisRepo.ZPageByScoreDesc(fetchLimit, cursor)
	if zerr == nil && len(zs) > 0 {
		tot := s.GetTotalCount(ctx)
		// Use the fixed MaxPageSize constant for capacity instead of the
		// user-derived limit (already clamped to <= MaxPageSize above). This keeps
		// any untrusted value out of make()'s size argument so CodeQL's allocation
		// taint analysis (CWE-770) is satisfied; capacity is only a growth hint.
		items := make([]map[string]interface{}, 0, MaxPageSize)
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

		// Optimize CIDR parsing: parse once outside the loop
		var queryNetwork *net.IPNet
		if q != "" {
			if _, network, err := net.ParseCIDR(query); err == nil {
				queryNetwork = network
			}
		}

		var currentCursor string
		for {
			ips := make([]string, len(zs))
			for i, z := range zs {
				ips[i] = z.Member.(string)
			}
			entries, err := s.redisRepo.GetIPEntries(ips)
			if err != nil {
				return items, currentCursor, tot, err
			}

			var lastAddedCursor string
			for i, z := range zs {
				if len(items) >= limit {
					break
				}

				if !s.matchesFilters(ips[i], entries[i], q, queryNetwork, countryList, addedBy, fromTime, toTime) {
					continue
				}

				items = append(items, map[string]interface{}{"ip": ips[i], "data": entries[i]})
				lastAddedCursor = fmt.Sprintf("%v:%s", z.Score, z.Member.(string))
			}

			if len(items) >= limit {
				if lastAddedCursor != "" {
					currentCursor = lastAddedCursor
				} else {
					currentCursor = next
				}
				break
			}
			currentCursor = next
			if currentCursor == "" {
				break
			}

			zs, next, zerr = s.redisRepo.ZPageByScoreDesc(fetchLimit, currentCursor)
			if zerr != nil {
				return items, currentCursor, tot, zerr
			}
			if len(zs) == 0 {
				break
			}
		}
		return items, currentCursor, tot, nil
	}

	// Fallback to hash listing if ZSET is empty/failed
	return s.ListIPsPaginated(ctx, limit, cursor, query)
}

func (s *IPService) exportFallback(ctx context.Context, query string, country string, addedBy string, fromTime, toTime time.Time) ([]map[string]interface{}, error) {
	all, err := s.redisRepo.HGetAllRaw("ips")
	if err != nil {
		return nil, err
	}

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

	// Optimize CIDR parsing
	var queryNetwork *net.IPNet
	if q != "" {
		if _, network, err := net.ParseCIDR(query); err == nil {
			queryNetwork = network
		}
	}

	for ip, raw := range all {
		var entry models.IPEntry
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			continue
		}

		if !s.matchesFilters(ip, &entry, q, queryNetwork, countryList, addedBy, fromTime, toTime) {
			continue
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

// BlockIP blocks a single IP.

func (s *IPService) BlockIP(ctx context.Context, ip string, reason string, username string, actorIP string, persist bool, duration time.Duration) (*models.IPEntry, error) {
	if s.redisRepo == nil {
		return nil, nil
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP format")
	}

	whitelist, _ := s.redisRepo.GetWhitelistedIPs()
	excluded, _ := s.redisRepo.GetExcludedEntries()

	valid, matchedEntry := s.isValidIPInternal(ip, addr, whitelist, excluded)
	if !valid {
		if matchedEntry != nil && matchedEntry.AlertEnabled {
			go s.triggerExcludedAlert(ctx, ip, reason, username, actorIP, *matchedEntry)
		}
		return nil, fmt.Errorf("IP is whitelisted or excluded")
	}

	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02 15:04:05 UTC")
	geo := s.GetGeoIP(ip)

	expiresAt := ""
	ttl := 0
	if !persist {
		ttl = int(duration.Seconds())
		if ttl <= 0 {
			ttl = 86400
		}
		expiresAt = now.Add(time.Duration(ttl) * time.Second).Format("2006-01-02 15:04:05 UTC")
	}

	entry := models.IPEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		Reason:      reason,
		AddedBy:     fmt.Sprintf("%s (%s)", username, actorIP),
		TTL:         ttl,
		ExpiresAt:   expiresAt,
		ThreatScore: s.CalculateThreatScore(ip, reason),
	}

	if persist && s.pgRepo != nil {
		_ = s.pgRepo.CreatePersistentBlock(ip, entry)
		_ = s.pgRepo.LogAction(username, "BLOCK_PERSISTENT", ip, reason)
	} else {
		if s.pgRepo != nil {
			_ = s.pgRepo.LogAction(username, "BLOCK_EPHEMERAL", ip, reason)
		}
	}

	err = s.redisRepo.ExecBlockAtomic(ip, entry, now)
	if err == nil {
		s.bloomMu.Lock()
		if s.bloomFilter != nil {
			s.bloomFilter.AddString(ip)
		}
		s.bloomMu.Unlock()
		return &entry, nil
	}
	return nil, err
}

// UnblockIP unblocks a single IP.
func (s *IPService) UnblockIP(ctx context.Context, ip string, username string) error {
	if s.redisRepo == nil {
		return nil
	}
	// Atomic unblock from Redis
	err := s.redisRepo.ExecUnblockAtomic(ip)
	if err != nil {
		return err
	}

	if s.pgRepo != nil {
		_ = s.pgRepo.DeletePersistentBlock(ip)
		_ = s.pgRepo.LogAction(username, "UNBLOCK", ip, "")
	}
	return nil
}

// WhitelistIP adds an IP to the whitelist.
func (s *IPService) WhitelistIP(ctx context.Context, ip string, reason string, username string, expiresAt string) error {
	geo := s.GetGeoIP(ip)
	entry := models.WhitelistEntry{
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Geolocation: geo,
		AddedBy:     username,
		Reason:      reason,
		ExpiresAt:   expiresAt,
	}
	if s.pgRepo != nil {
		_ = s.pgRepo.LogAction(username, "WHITELIST", ip, reason)
	}
	return s.redisRepo.WhitelistIP(ip, entry)
}

// RemoveWhitelist removes an IP from the whitelist.
func (s *IPService) RemoveWhitelist(ctx context.Context, ip string, username string) error {
	if s.pgRepo != nil {
		_ = s.pgRepo.LogAction(username, "UNWHITELIST", ip, "")
	}
	return s.redisRepo.RemoveFromWhitelist(ip)
}

// AddExcluded adds a value (IP, CIDR, or FQDN) to the excluded list. The type is
// auto-detected and the value canonicalized. expiresAt is optional (RFC3339);
// an empty string means the exclusion never expires.
func (s *IPService) AddExcluded(ctx context.Context, value string, reason string, username string, expiresAt string, alertEnabled bool) error {
	if s.redisRepo == nil {
		return fmt.Errorf("storage unavailable")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value required")
	}

	typ := classifyExclusionType(value)
	// Canonicalize so lookups match regardless of input formatting.
	switch typ {
	case "cidr":
		if p, err := netip.ParsePrefix(value); err == nil {
			value = p.Masked().String()
		}
	case "ip":
		if a, err := netip.ParseAddr(value); err == nil {
			value = a.Unmap().String()
		}
	case "fqdn":
		value = strings.ToLower(strings.TrimSuffix(value, "."))
	case "wildcard":
		value = "*." + strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(value, "*."), "."))
	}

	entry := models.ExcludedEntry{
		Timestamp:    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Value:        value,
		Type:         typ,
		AddedBy:      username,
		Reason:       reason,
		ExpiresAt:    expiresAt,
		AlertEnabled: alertEnabled,
	}

	if typ == "fqdn" {
		// Drop any stale cached resolution so the new entry is honored promptly.
		s.fqdnCacheMu.Lock()
		delete(s.fqdnCache, value)
		s.fqdnCacheMu.Unlock()
	}

	if s.pgRepo != nil && username != "system" {
		_ = s.pgRepo.LogAction(username, "EXCLUDE", value, reason)
	}
	return s.redisRepo.AddExcluded(value, entry)
}

// RemoveExcluded removes a value from the excluded list.
func (s *IPService) RemoveExcluded(ctx context.Context, value string, username string) error {
	if s.redisRepo == nil {
		return fmt.Errorf("storage unavailable")
	}
	value = strings.TrimSpace(value)
	if s.pgRepo != nil {
		_ = s.pgRepo.LogAction(username, "UNEXCLUDE", value, "")
	}
	return s.redisRepo.RemoveExcluded(value)
}

// GetIPDetails retrieves current and historical details for an IP.
func (s *IPService) GetIPDetails(ctx context.Context, ip string) (map[string]interface{}, error) {
	entry, err := s.redisRepo.GetIPEntry(ip)
	var history []models.AuditLog
	if s.pgRepo != nil {
		history, _ = s.pgRepo.GetIPHistory(ip)
	}
	if history == nil {
		history = []models.AuditLog{}
	}

	res := map[string]interface{}{
		"ip":      ip,
		"history": history,
	}
	if err == nil && entry != nil {
		res["current"] = entry
	}
	return res, nil
}
