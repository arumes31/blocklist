package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/bytedance/sonic"
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
	"unicode/utf8"

	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
	zlog "github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

const MaxPageSize = 1000

// maxFilterScanPerPage bounds how many index entries one filtered page may
// examine before returning a resume cursor.
const maxFilterScanPerPage = 20000

type IPService struct {
	redisRepo      *repository.RedisRepository
	pgRepo         *repository.PostgresRepository
	webhookService *WebhookService
	mailService    *MailService
	accountLabels  *AccountLabels
	blockedRanges  []netip.Prefix
	geoipReader    *geoip2.Reader
	asnReader      *geoip2.Reader
	fqdnCache      map[string]fqdnResolution
	fqdnCacheMu    sync.Mutex
	ptrCache       map[netip.Addr]ptrResolution
	ptrCacheMu     sync.Mutex
	dnsResolver    exclusionDNSResolver
	fqdnLookups    singleflight.Group
	ptrLookups     singleflight.Group
	nextFQDNPrune  time.Time // protected by fqdnCacheMu
	nextPTRPrune   time.Time // protected by ptrCacheMu
	statsMu        sync.Mutex
	statsCached    *statsSnapshot
	statsRefresh   *statsRefresh
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
		fqdnCache:     make(map[string]fqdnResolution),
		ptrCache:      make(map[netip.Addr]ptrResolution),
	}
	return svc
}

func (s *IPService) SetWebhookService(wh *WebhookService) {
	s.webhookService = wh
}

func (s *IPService) SetMailService(ms *MailService) {
	s.mailService = ms
}

// SetAccountLabels shows Entra account keys by sign-in name in returned records,
// searches and alerts. Stored records keep the key.
func (s *IPService) SetAccountLabels(labels *AccountLabels) {
	s.accountLabels = labels
}

func (s *IPService) triggerExcludedAlert(ctx context.Context, ip string, reason string, addedBy string, actorIP string, entry models.ExcludedEntry) {
	addedBy = s.accountLabels.Snapshot(ctx).Label(addedBy)
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
		data, _ := sonic.Marshal(payload)
		country := ""
		if geo := s.GetGeoIP(ip); geo != nil {
			country = geo.Country
		}
		s.webhookService.Notify(ctx, "excluded_block_attempt", country, string(data))
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

// IsBlocked reports whether ipStr has a live block. Shared Redis state is
// always consulted: another server process may have added the block, so no
// process-local cache can prove an address is not blocked.
func (s *IPService) IsBlocked(ipStr string) bool {
	if s.redisRepo == nil {
		return false
	}
	for attempt := 0; attempt < 3; attempt++ {
		entry, err := s.redisRepo.GetIPEntry(ipStr)
		if err != nil || entry == nil {
			return false
		}
		if entry.ExpiresAt == "" {
			return true
		}
		exp, err := time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
		if err != nil || !time.Now().UTC().After(exp) {
			return true
		}
		// Remove only the expired record that was read; a renewal written in
		// the meantime survives and is evaluated on the next pass.
		result, err := s.redisRepo.RemoveIfUnchanged("ips", ipStr, entry.Timestamp, entry.ExpiresAt)
		if err != nil || result != repository.RemoveChanged {
			return false
		}
	}
	return true // The record keeps changing under us; fail closed.
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

// whitelisted reports whether ip has a live whitelist entry: an exact key (as
// given or canonical) or a CIDR entry containing it. Expired entries found on
// the way are removed lazily.
func (s *IPService) whitelisted(ipStr string, ip netip.Addr, whitelist map[string]models.WhitelistEntry) bool {
	if len(whitelist) == 0 {
		return false
	}
	live := func(key string, entry models.WhitelistEntry) bool {
		if entry.ExpiresAt == "" {
			return true
		}
		exp, err := time.Parse(time.RFC3339, entry.ExpiresAt)
		if err == nil && time.Now().After(exp) {
			if s.redisRepo != nil {
				// A renewal written since the snapshot is kept, but this
				// decision still uses the snapshot; the next check sees it.
				_, _ = s.redisRepo.RemoveIfUnchanged("ips_webhook2_whitelist", key, entry.Timestamp, entry.ExpiresAt)
			}
			return false
		}
		return true
	}
	for _, key := range []string{ipStr, ip.Unmap().String()} {
		if entry, ok := whitelist[key]; ok && live(key, entry) {
			return true
		}
	}
	addr := ip.Unmap()
	for key, entry := range whitelist {
		if !strings.Contains(key, "/") {
			continue
		}
		if prefix, err := netip.ParsePrefix(key); err == nil && prefixContains(prefix, addr) && live(key, entry) {
			return true
		}
	}
	return false
}

func (s *IPService) isValidIPInternal(ipStr string, ip netip.Addr, whitelist map[string]models.WhitelistEntry, excluded map[string]models.ExcludedEntry) (bool, *models.ExcludedEntry) {
	if s.whitelisted(ipStr, ip, whitelist) {
		return false, nil
	}

	// Excluded list: IPs, subnets, or FQDNs that must never be blocked.
	if entry := s.isExcludedMatch(ip, excluded); entry != nil {
		return false, entry
	}

	for _, prefix := range s.blockedRanges {
		if prefixContains(prefix, ip) {
			return false, nil
		}
	}

	return true, nil
}

// prefixContains compares an address with a prefix in both address families,
// so an IPv4-mapped IPv6 spelling of an address (or of a configured prefix)
// cannot slip past a rule written in the other form.
func prefixContains(prefix netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	if prefix.Contains(addr) {
		return true
	}
	return addr.Is4() && prefix.Contains(netip.AddrFrom16(addr.As16()))
}

// canonicalPrefix stores IPv4-mapped prefixes that lie inside ::ffff:0:0/96 as
// the equivalent IPv4 prefix, so stored rules use the same family as the
// unmapped addresses they are compared with.
func canonicalPrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
	}
	return prefix
}

// ErrInvalidBlockInput reports an address or reason that cannot be enforced
// and recorded faithfully.
var ErrInvalidBlockInput = errors.New("invalid address or reason")

// ErrBlockShortens reports that an existing block lasts longer than the
// requested one. Shortening a block requires unblocking it first.
var ErrBlockShortens = repository.ErrBlockShortens

// canonicalBlockAddress parses an address for enforcement. Zones are rejected
// (they are free text that would reach the public feed) and IPv4-mapped
// addresses are stored as IPv4, matching how protection rules compare them.
func canonicalBlockAddress(ipStr string) (netip.Addr, string, bool) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, "", false
	}
	addr = addr.Unmap()
	return addr, addr.String(), true
}

// validAuditText reports whether text can be stored in PostgreSQL TEXT
// columns: valid UTF-8 without NUL characters. Rejecting it up front stops a
// caller from making the audit insert fail while enforcement proceeds.
func validAuditText(text string) bool {
	return utf8.ValidString(text) && !strings.ContainsRune(text, 0)
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
	// Removal is conditional on the snapshot so a renewal is never deleted.
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
			_, _ = s.redisRepo.RemoveIfUnchanged("ips_webhook2_excluded", value, entry.Timestamp, entry.ExpiresAt)
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
			if prefix, err := netip.ParsePrefix(value); err == nil && prefixContains(prefix, ip) {
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
	// One DNS budget covers the whole reverse-and-forward chain, and only a
	// few PTR candidates are confirmed, so a hostile PTR response cannot keep
	// a blocking decision waiting on many sequential lookups.
	deadline := time.Now().Add(wildcardMatchBudget)
	checked := 0
	for _, name := range s.lookupPTR(ip) {
		if name != base && !strings.HasSuffix(name, suffix) {
			continue
		}
		if checked >= maxWildcardCandidates || !time.Now().Before(deadline) {
			return false
		}
		checked++
		if _, ok := s.resolveFQDN(name)[ip]; ok {
			return true
		}
	}
	return false
}

const (
	// maxWildcardCandidates bounds forward confirmations per wildcard decision.
	maxWildcardCandidates = 4
	// wildcardMatchBudget bounds the time one wildcard decision spends on DNS.
	wildcardMatchBudget = 5 * time.Second
)

// resolveAndCache resolves host to its current address set, stores it in the
// FQDN cache, and returns the set along with any resolution error.
func (s *IPService) resolveAndCache(host string) (map[netip.Addr]struct{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := s.exclusionResolver().LookupNetIP(ctx, "ip", host)

	addrs := make(map[netip.Addr]struct{}, len(ips))
	for _, a := range ips {
		addrs[a.Unmap()] = struct{}{}
	}
	ttl := fqdnCacheTTL
	if err != nil || len(addrs) == 0 {
		ttl = fqdnCacheNegTTL
	}

	s.fqdnCacheMu.Lock()
	now := time.Now()
	s.pruneFQDNCacheLocked(now)
	s.fqdnCache[host] = fqdnResolution{addrs: addrs, expires: now.Add(ttl)}
	s.fqdnCacheMu.Unlock()
	return addrs, err
}

// resolveFQDN returns the set of addresses host currently resolves to, using a
// short-lived cache so block-time exclusion checks do not hit DNS on every call.
func (s *IPService) resolveFQDN(host string) map[netip.Addr]struct{} {
	if addrs, ok := s.cachedFQDN(host); ok {
		return addrs
	}
	result, _, _ := s.fqdnLookups.Do(host, func() (any, error) {
		// Another lookup may have filled the cache while we joined the group.
		if addrs, ok := s.cachedFQDN(host); ok {
			return addrs, nil
		}
		return s.resolveAndCache(host)
	})
	addrs, _ := result.(map[netip.Addr]struct{})
	return addrs
}

// lookupPTR returns the lower-cased reverse-DNS names for ip, using a cache.
func (s *IPService) lookupPTR(ip netip.Addr) []string {
	if names, ok := s.cachedPTR(ip); ok {
		return names
	}
	result, _, _ := s.ptrLookups.Do(ip.String(), func() (any, error) {
		if names, ok := s.cachedPTR(ip); ok {
			return names, nil
		}
		return s.resolveAndCachePTR(ip), nil
	})
	names, _ := result.([]string)
	return names
}

func (s *IPService) resolveAndCachePTR(ip netip.Addr) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := s.exclusionResolver().LookupAddr(ctx, ip.String())

	names := make([]string, 0, len(raw))
	for _, n := range raw {
		names = append(names, strings.ToLower(strings.TrimSuffix(n, ".")))
	}
	ttl := fqdnCacheTTL
	if err != nil || len(names) == 0 {
		ttl = fqdnCacheNegTTL
	}

	s.ptrCacheMu.Lock()
	now := time.Now()
	s.prunePTRCacheLocked(now)
	s.ptrCache[ip] = ptrResolution{names: names, expires: now.Add(ttl)}
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

		// Write only the resolution fields, and only onto the record that was
		// resolved: a deleted or edited exclusion must not be restored.
		updated, err := s.redisRepo.UpdateExcludedResolution(value, entry)
		if err != nil {
			zlog.Error().Err(err).Str("fqdn", value).Msg("excluded: failed to persist resolution result")
		} else if !updated {
			zlog.Debug().Str("fqdn", value).Msg("excluded: entry changed during resolution; result discarded")
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

// ListIPsPaginated shares complete search and cursor handling with advanced filters.
func (s *IPService) ListIPsPaginated(ctx context.Context, limit int, cursor string, query string) ([]map[string]interface{}, string, int, error) {
	return s.ListIPsPaginatedAdvanced(ctx, limit, cursor, query, "", "", "", "")
}

func (s *IPService) listIPsHashFallback(ctx context.Context, limit int, cursor string, opts *filterOptions) ([]map[string]interface{}, string, int, error) {
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
		if err := sonic.UnmarshalString(raw, &e); err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, "", 0, err
		}
		if !s.matchesFilters(ip, &e, opts) {
			continue
		}
		var ts int64
		if t, err := time.Parse("2006-01-02 15:04:05 UTC", e.Timestamp); err == nil {
			ts = t.Unix()
		}
		list = append(list, pair{ip: ip, e: e, ts: ts})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ts == list[j].ts {
			return list[i].ip > list[j].ip
		}
		return list[i].ts > list[j].ts
	})
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
		p.e.AddedBy = opts.labels.Label(p.e.AddedBy)
		itemsOut = append(itemsOut, map[string]interface{}{"ip": p.ip, "data": p.e})
	}
	nextCursor := ""
	if end < len(list) {
		nextCursor = strconv.Itoa(end)
	}
	return itemsOut, nextCursor, len(list), nil
}

// computeStats reads uncached counters and top-ten rankings from Redis. Reason
// rankings group trimmed, case-insensitive values while retaining a stable display
// label. A missing repository returns zero values; Redis failures are returned.
func (s *IPService) computeStats(ctx context.Context) (hour int, day int, totalEver int, activeBlocks int, top []struct {
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
	reasonMap := make(map[string]reasonStat)

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
		if reason := strings.TrimSpace(entry.Reason); reason != "" {
			key := strings.ToLower(reason)
			stat := reasonMap[key]
			stat.Count++
			// Keep a stable original-cased label regardless of Redis map iteration.
			if stat.Reason == "" || reason < stat.Reason {
				stat.Reason = reason
			}
			reasonMap[key] = stat
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

	for _, stat := range reasonMap {
		topReason = append(topReason, stat)
	}
	sort.Slice(topReason, func(i, j int) bool { return topReason[i].Count > topReason[j].Count })
	if len(topReason) > 10 {
		topReason = topReason[:10]
	}

	h, hourErr := s.redisRepo.CountLastHour()
	d, dayErr := s.redisRepo.CountLastDay()
	totalEver, totalErr := s.redisRepo.CountTotalEver()
	wh, webhookErr := s.redisRepo.CountWebhooksLastHour()
	lb, lastBlockErr := s.redisRepo.GetLastBlockTime()
	bm, minuteErr := s.redisRepo.CountBlocksLastMinute()

	wips, whitelistErr := s.redisRepo.GetWhitelistedIPs()
	whitelistCount = len(wips)

	return h, d, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, whitelistCount,
		errors.Join(hourErr, dayErr, totalErr, webhookErr, lastBlockErr, minuteErr, whitelistErr)
}

// ExportIPs returns all IPs matching the filters for export purposes.
func (s *IPService) ExportIPs(ctx context.Context, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, error) {
	if s.redisRepo == nil {
		return nil, nil
	}
	// For export, we fetch a large batch or iterate.
	// Simple implementation: fetch up to 10k items.

	opts := s.prepareFilterOptions(query, country, addedBy, from, to)
	opts.labels = s.accountLabels.Snapshot(ctx)

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
		return s.exportFallback(ctx, opts)
	}
	if err != nil {
		return nil, err
	}

	items := make([]map[string]interface{}, 0)

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
			if !s.matchesFilters(ips[j], entry, opts) {
				continue
			}

			// Ensure we always store a pointer to IPEntry
			entry.AddedBy = opts.labels.Label(entry.AddedBy)
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
	if !validAuditText(reason) {
		return ErrInvalidBlockInput
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

	// Canonicalize and deduplicate input IPs. Unparseable or zoned entries are
	// skipped; only canonical addresses are stored and published.
	uniqueIPs := make([]string, 0, len(ips))
	seen := make(map[string]struct{})
	for _, ip := range ips {
		_, canonical, ok := canonicalBlockAddress(ip)
		if !ok {
			continue
		}
		if _, dup := seen[canonical]; !dup {
			seen[canonical] = struct{}{}
			uniqueIPs = append(uniqueIPs, canonical)
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
		if err := s.pgRepo.BulkCreatePersistentBlocks(validIPs, validEntries); err != nil {
			zlog.Error().Err(err).Int("count", len(validIPs)).Msg("BulkBlock: failed to store persistent blocks")
		}
		logAuditFailure(s.pgRepo.BulkLogAction(addedBy, "BLOCK_PERSISTENT", validIPs, reason), "BLOCK_PERSISTENT")
	} else if s.pgRepo != nil {
		logAuditFailure(s.pgRepo.BulkLogAction(addedBy, "BLOCK_EPHEMERAL", validIPs, reason), "BLOCK_EPHEMERAL")
	}
	return s.redisRepo.ExecBulkBlockAtomic(validIPs, validEntries, now)
}

// logAuditFailure reports an audit insert that failed after input validation,
// so a missing event-history record is visible to operators.
func logAuditFailure(err error, action string) {
	if err != nil {
		zlog.Error().Err(err).Str("action", action).Msg("Failed to record enforcement event in the audit log")
	}
}

// canonicalUnblockKeys returns the stored keys an unblock request may refer
// to: the canonical address and, for older records, the spelling as given.
func canonicalUnblockKeys(ips []string) []string {
	keys := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	add := func(key string) {
		if _, dup := seen[key]; !dup {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil || addr.Zone() != "" || !validAuditText(ip) {
			continue
		}
		add(addr.Unmap().String())
		add(ip)
	}
	return keys
}

// BulkUnblock unblocks multiple IPs at once.
func (s *IPService) BulkUnblock(ctx context.Context, ips []string, actor string) error {
	if s.redisRepo == nil || len(ips) == 0 {
		return nil
	}
	// Every member is validated before state changes, so one invalid value
	// cannot make the audit insert fail after the unblock was applied.
	keys := canonicalUnblockKeys(ips)
	if len(keys) == 0 {
		return ErrInvalidBlockInput
	}

	err := s.redisRepo.ExecBulkUnblockAtomic(keys)
	if err != nil {
		return err
	}

	if s.pgRepo != nil {
		if err := s.pgRepo.BulkDeletePersistentBlocks(keys); err != nil {
			zlog.Error().Err(err).Int("count", len(keys)).Msg("BulkUnblock: failed to delete persistent blocks")
		}
		logAuditFailure(s.pgRepo.BulkLogAction(actor, "UNBLOCK", keys, "bulk action"), "UNBLOCK")
	}
	return nil
}

// Country filter bounds: more distinct values than there are countries, or
// longer than any country name, cannot match anything useful.
const (
	maxCountryFilters      = 300
	maxCountryFilterLength = 64
)

type filterOptions struct {
	query        string
	queryField   string
	queryASN     uint64
	queryNetwork *net.IPNet
	countries    map[string]struct{}
	addedBy      string
	fromTime     time.Time
	toTime       time.Time
	labels       *AccountLabelSet
}

// prepareFilterOptions normalizes filters shared by pagination and exports.
// Qualified asn: and reason: queries use exact matching; other queries retain
// text and CIDR matching. Invalid dates leave their bounds unset, while invalid
// or zero ASNs remain non-matching qualified queries.
func (s *IPService) prepareFilterOptions(query, country, addedBy, from, to string) *filterOptions {
	opts := &filterOptions{}
	if from != "" {
		opts.fromTime, _ = time.Parse(time.RFC3339, from)
	}
	if to != "" {
		opts.toTime, _ = time.Parse(time.RFC3339, to)
	}
	opts.query = strings.ToLower(strings.TrimSpace(query))
	field, value, qualified := strings.Cut(opts.query, ":")
	field = strings.TrimSpace(field)
	insightField := field == "asn" || field == "reason"
	if qualified && insightField {
		opts.queryField = field
		opts.query = strings.TrimSpace(value)
		if field == "asn" {
			if asn, err := strconv.ParseUint(opts.query, 10, 32); err == nil {
				opts.queryASN = asn
			}
		}
	}
	if country != "" {
		// A set keeps membership constant-time per record; the bounds stop a
		// huge query string from multiplying the cost of every scanned record.
		opts.countries = make(map[string]struct{})
		for _, c := range strings.Split(country, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(c))
			if trimmed == "" || len(trimmed) > maxCountryFilterLength {
				continue
			}
			if len(opts.countries) >= maxCountryFilters {
				break
			}
			opts.countries[trimmed] = struct{}{}
		}
		if len(opts.countries) == 0 {
			// Only invalid values were given: match nothing rather than everything.
			opts.countries[""] = struct{}{}
		}
	}
	opts.addedBy = strings.ToLower(strings.TrimSpace(addedBy))
	if opts.query != "" && opts.queryField == "" {
		if _, network, err := net.ParseCIDR(opts.query); err == nil {
			opts.queryNetwork = network
		}
	}
	return opts
}

// matchesFilters applies all constraints from non-nil, prepared filter options
// without modifying the entry. Exact reasons ignore case and surrounding space;
// ordinary queries match text or CIDR. Nil entries never match, and entries with
// unparseable timestamps are not rejected by date bounds.
func (s *IPService) matchesFilters(ip string, entry *models.IPEntry, opts *filterOptions) bool {
	if entry == nil {
		return false
	}

	// Ranking shortcuts use exact fields; ordinary searches retain text/CIDR matching.
	switch {
	case opts.queryField == "asn":
		if opts.queryASN == 0 || entry.Geolocation == nil || uint64(entry.Geolocation.ASN) != opts.queryASN {
			return false
		}
	case opts.queryField == "reason":
		if opts.query == "" || strings.ToLower(strings.TrimSpace(entry.Reason)) != opts.query {
			return false
		}
	case opts.query != "":
		matches := false
		// Text match on fields; Added By matches its stored key or shown name.
		if strings.Contains(strings.ToLower(ip), opts.query) ||
			strings.Contains(strings.ToLower(entry.Reason), opts.query) ||
			strings.Contains(strings.ToLower(entry.AddedBy), opts.query) ||
			strings.Contains(strings.ToLower(opts.labels.Label(entry.AddedBy)), opts.query) ||
			(entry.Geolocation != nil && strings.Contains(strings.ToLower(entry.Geolocation.Country), opts.query)) {
			matches = true
		}

		// Smart Match: CIDR
		if !matches && opts.queryNetwork != nil {
			if parsedIP := net.ParseIP(ip); parsedIP != nil && opts.queryNetwork.Contains(parsedIP) {
				matches = true
			}
		}

		if !matches {
			return false
		}
	}

	// 2. Country filter
	if len(opts.countries) > 0 {
		if entry.Geolocation == nil {
			return false
		}
		if _, ok := opts.countries[strings.ToLower(entry.Geolocation.Country)]; !ok || entry.Geolocation.Country == "" {
			return false
		}
	}

	// 3. AddedBy filter
	if opts.addedBy != "" {
		if !strings.EqualFold(entry.AddedBy, opts.addedBy) &&
			!strings.EqualFold(opts.labels.Label(entry.AddedBy), opts.addedBy) {
			return false
		}
	}

	// 4. Date range filters
	if !opts.fromTime.IsZero() || !opts.toTime.IsZero() {
		ts, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
		if err == nil {
			if !opts.fromTime.IsZero() && ts.Before(opts.fromTime) {
				return false
			}
			if !opts.toTime.IsZero() && ts.After(opts.toTime) {
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
	if limit <= 0 || limit > MaxPageSize {
		limit = MaxPageSize
	}
	opts := s.prepareFilterOptions(query, country, addedBy, from, to)
	opts.labels = s.accountLabels.Snapshot(ctx)
	total, err := s.redisRepo.GetZSetCount()
	if err != nil {
		return nil, "", 0, err
	}
	// An exhausted tuple cursor must never restart at the hash's first page.
	if total == 0 && !strings.Contains(cursor, ":") {
		return s.listIPsHashFallback(ctx, limit, cursor, opts)
	}
	fetchLimit := limit + 1
	if query != "" || country != "" || addedBy != "" || from != "" || to != "" {
		fetchLimit = 500
	}
	items := make([]map[string]interface{}, 0, MaxPageSize)
	lastMatch := ""
	scanned := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, "", total, err
		}
		// A filter that matches little would otherwise walk the whole index in
		// one request; return what was found with a cursor to resume from.
		if scanned >= maxFilterScanPerPage {
			return items, cursor, total, nil
		}
		zs, next, err := s.redisRepo.ZPageByScoreDesc(fetchLimit, cursor)
		scanned += len(zs)
		if err != nil {
			return nil, "", total, err
		}
		ips := make([]string, len(zs))
		for i, z := range zs {
			ips[i] = z.Member.(string)
		}
		entries, err := s.redisRepo.GetIPEntries(ips)
		if err != nil {
			return nil, "", total, err
		}
		for i, z := range zs {
			if !s.matchesFilters(ips[i], entries[i], opts) {
				continue
			}
			// Look ahead to an actual match, so exact-sized final pages end here.
			if len(items) == limit {
				return items, lastMatch, total, nil
			}
			entries[i].AddedBy = opts.labels.Label(entries[i].AddedBy)
			items = append(items, map[string]interface{}{"ip": ips[i], "data": entries[i]})
			lastMatch = fmt.Sprintf("%v:%s", z.Score, ips[i])
		}
		if next == "" {
			return items, "", total, nil
		}
		cursor = next
	}
}

func (s *IPService) exportFallback(ctx context.Context, opts *filterOptions) ([]map[string]interface{}, error) {
	all, err := s.redisRepo.HGetAllRaw("ips")
	if err != nil {
		return nil, err
	}

	items := make([]map[string]interface{}, 0)

	for ip, raw := range all {
		var entry models.IPEntry
		if err := sonic.UnmarshalString(raw, &entry); err != nil {
			continue
		}

		if !s.matchesFilters(ip, &entry, opts) {
			continue
		}

		entry.AddedBy = opts.labels.Label(entry.AddedBy)
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

	addr, canonical, ok := canonicalBlockAddress(ip)
	if !ok {
		return nil, fmt.Errorf("invalid IP format")
	}
	if !validAuditText(reason) {
		return nil, ErrInvalidBlockInput
	}
	ip = canonical

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

	// A block may extend, but never shorten, an existing block: shortening is
	// removal and needs unblock rights. The Redis script enforces this
	// atomically; this early check avoids recording an event that is refused.
	if current, err := s.redisRepo.GetIPEntry(ip); err == nil && current != nil && outlasts(current.ExpiresAt, expiresAt) {
		return nil, ErrBlockShortens
	}

	if persist && s.pgRepo != nil {
		if err := s.pgRepo.CreatePersistentBlock(ip, entry); err != nil {
			zlog.Error().Err(err).Str("ip", ip).Msg("BlockIP: failed to store persistent block")
		}
		logAuditFailure(s.pgRepo.LogAction(username, "BLOCK_PERSISTENT", ip, reason), "BLOCK_PERSISTENT")
	} else if s.pgRepo != nil {
		logAuditFailure(s.pgRepo.LogAction(username, "BLOCK_EPHEMERAL", ip, reason), "BLOCK_EPHEMERAL")
	}

	if err := s.redisRepo.ExecBlockAtomic(ip, entry, now); err != nil {
		return nil, err
	}
	return &entry, nil
}

// outlasts reports whether a block expiring at current lasts longer than one
// expiring at replacement ("" = permanent; fixed-width UTC layout).
func outlasts(current, replacement string) bool {
	if replacement == "" {
		return false
	}
	return current == "" || current > replacement
}

// UnblockIP unblocks a single IP.
func (s *IPService) UnblockIP(ctx context.Context, ip string, username string) error {
	if s.redisRepo == nil {
		return nil
	}
	keys := canonicalUnblockKeys([]string{ip})
	if len(keys) == 0 {
		return ErrInvalidBlockInput
	}
	// Atomic unblock from Redis (canonical key and, for older records, the
	// spelling as given).
	for _, key := range keys {
		if err := s.redisRepo.ExecUnblockAtomic(key); err != nil {
			return err
		}
	}

	if s.pgRepo != nil {
		for _, key := range keys {
			if err := s.pgRepo.DeletePersistentBlock(key); err != nil {
				zlog.Error().Err(err).Str("ip", key).Msg("UnblockIP: failed to delete persistent block")
			}
		}
		logAuditFailure(s.pgRepo.LogAction(username, "UNBLOCK", keys[0], ""), "UNBLOCK")
	}
	return nil
}

// CanonicalWhitelistKey normalizes an IP or CIDR so equivalent spellings (for
// example IPv6 zero compression or unmasked prefixes) share one whitelist key.
func CanonicalWhitelistKey(ip string) string {
	ip = strings.TrimSpace(ip)
	if p, err := netip.ParsePrefix(ip); err == nil {
		return canonicalPrefix(p).String()
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.Unmap().String()
	}
	return ip
}

func (s *IPService) whitelistEntry(ip, reason, username, expiresAt string) models.WhitelistEntry {
	return models.WhitelistEntry{
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Geolocation: s.GetGeoIP(ip),
		AddedBy:     username,
		Reason:      reason,
		ExpiresAt:   expiresAt,
	}
}

// WhitelistIP adds or replaces a whitelist entry.
func (s *IPService) WhitelistIP(ctx context.Context, ip string, reason string, username string, expiresAt string) error {
	ip = CanonicalWhitelistKey(ip)
	entry := s.whitelistEntry(ip, reason, username, expiresAt)
	if s.pgRepo != nil {
		_ = s.pgRepo.LogAction(username, "WHITELIST", ip, reason)
	}
	return s.redisRepo.WhitelistIP(ip, entry)
}

// WhitelistIPIfAbsent is WhitelistIP for create-only callers: it atomically
// refuses to replace an existing entry and reports whether one was created.
func (s *IPService) WhitelistIPIfAbsent(ctx context.Context, ip string, reason string, username string, expiresAt string) (bool, error) {
	ip = CanonicalWhitelistKey(ip)
	created, err := s.redisRepo.WhitelistIPIfAbsent(ip, s.whitelistEntry(ip, reason, username, expiresAt))
	if err == nil && created && s.pgRepo != nil {
		_ = s.pgRepo.LogAction(username, "WHITELIST", ip, reason)
	}
	return created, err
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
	entry, err := s.prepareExcluded(value, reason, username, expiresAt, alertEnabled)
	if err != nil {
		return err
	}
	if s.pgRepo != nil && username != "system" {
		_ = s.pgRepo.LogAction(username, "EXCLUDE", entry.Value, reason)
	}
	return s.redisRepo.AddExcluded(entry.Value, entry)
}

// AddSystemExcluded creates or renews a feed-owned exclusion. It never
// replaces an operator's exclusion and reports whether it wrote the entry.
func (s *IPService) AddSystemExcluded(ctx context.Context, value, reason, expiresAt string) (bool, error) {
	entry, err := s.prepareExcluded(value, reason, "system", expiresAt, false)
	if err != nil {
		return false, err
	}
	return s.redisRepo.UpsertSystemExcluded(entry.Value, entry)
}

// AddExcludedIfAbsent is AddExcluded for create-only callers: it atomically
// refuses to replace an existing exclusion and reports whether one was created.
func (s *IPService) AddExcludedIfAbsent(ctx context.Context, value string, reason string, username string, expiresAt string, alertEnabled bool) (bool, error) {
	entry, err := s.prepareExcluded(value, reason, username, expiresAt, alertEnabled)
	if err != nil {
		return false, err
	}
	created, err := s.redisRepo.AddExcludedIfAbsent(entry.Value, entry)
	if err == nil && created && s.pgRepo != nil && username != "system" {
		_ = s.pgRepo.LogAction(username, "EXCLUDE", entry.Value, reason)
	}
	return created, err
}

// CanonicalExclusion returns the canonical stored form of an exclusion value
// and its type, so lookups match regardless of input formatting.
func CanonicalExclusion(value string) (string, string) {
	value = strings.TrimSpace(value)
	typ := classifyExclusionType(value)
	switch typ {
	case "cidr":
		if p, err := netip.ParsePrefix(value); err == nil {
			value = canonicalPrefix(p).String()
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
	return value, typ
}

func (s *IPService) prepareExcluded(value, reason, username, expiresAt string, alertEnabled bool) (models.ExcludedEntry, error) {
	if s.redisRepo == nil {
		return models.ExcludedEntry{}, fmt.Errorf("storage unavailable")
	}
	if strings.TrimSpace(value) == "" {
		return models.ExcludedEntry{}, fmt.Errorf("value required")
	}
	value, typ := CanonicalExclusion(value)
	if typ == "fqdn" {
		// Drop any stale cached resolution so the new entry is honored promptly.
		s.fqdnCacheMu.Lock()
		delete(s.fqdnCache, value)
		s.fqdnCacheMu.Unlock()
		s.fqdnLookups.Forget(value)
	}
	return models.ExcludedEntry{
		Timestamp:    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Value:        value,
		Type:         typ,
		AddedBy:      username,
		Reason:       reason,
		ExpiresAt:    expiresAt,
		AlertEnabled: alertEnabled,
	}, nil
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
	// Only addresses have IP details; other targets (account names, roles)
	// belong to the system audit log.
	if addr, err := netip.ParseAddr(ip); err != nil || addr.Zone() != "" {
		return nil, fmt.Errorf("invalid IP format")
	}
	entry, err := s.redisRepo.GetIPEntry(ip)
	var history []models.AuditLog
	if s.pgRepo != nil {
		history, _ = s.pgRepo.GetIPHistory(ip)
	}
	if history == nil {
		history = []models.AuditLog{}
	}
	labels := s.accountLabels.Snapshot(ctx)
	for i := range history {
		history[i].Actor = labels.Label(history[i].Actor)
	}
	if entry != nil {
		entry.AddedBy = labels.Label(entry.AddedBy)
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
