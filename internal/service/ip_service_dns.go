package service

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type exclusionDNSResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
	LookupAddr(context.Context, string) ([]string, error)
}

func (s *IPService) exclusionResolver() exclusionDNSResolver {
	if s.dnsResolver != nil {
		return s.dnsResolver
	}
	return net.DefaultResolver
}

func (s *IPService) cachedFQDN(host string) (map[netip.Addr]struct{}, bool) {
	s.fqdnCacheMu.Lock()
	defer s.fqdnCacheMu.Unlock()
	now := time.Now()
	s.pruneFQDNCacheLocked(now)
	cached, ok := s.fqdnCache[host]
	return cached.addrs, ok && now.Before(cached.expires)
}

func (s *IPService) cachedPTR(ip netip.Addr) ([]string, bool) {
	s.ptrCacheMu.Lock()
	defer s.ptrCacheMu.Unlock()
	now := time.Now()
	s.prunePTRCacheLocked(now)
	cached, ok := s.ptrCache[ip]
	return cached.names, ok && now.Before(cached.expires)
}

// Sweep at most once a minute during cache use, independently in each process.
// This needs no background goroutine or scheduler/Redis lock. It only removes
// already expired entries; live values keep their original positive/negative
// TTLs. Without sweeping, one-off PTR addresses accumulate for the process's
// entire lifetime. Cache hits do not extend the lifetime of a DNS result.
func (s *IPService) pruneFQDNCacheLocked(now time.Time) {
	if now.Before(s.nextFQDNPrune) {
		return
	}
	for host, cached := range s.fqdnCache {
		if !now.Before(cached.expires) {
			delete(s.fqdnCache, host)
		}
	}
	if len(s.fqdnCache) == 0 {
		// Release the backing storage too when a previous burst has expired.
		s.fqdnCache = make(map[string]fqdnResolution)
	}
	s.nextFQDNPrune = now.Add(time.Minute)
}

func (s *IPService) prunePTRCacheLocked(now time.Time) {
	if now.Before(s.nextPTRPrune) {
		return
	}
	for ip, cached := range s.ptrCache {
		if !now.Before(cached.expires) {
			delete(s.ptrCache, ip)
		}
	}
	if len(s.ptrCache) == 0 {
		s.ptrCache = make(map[netip.Addr]ptrResolution)
	}
	s.nextPTRPrune = now.Add(time.Minute)
}
