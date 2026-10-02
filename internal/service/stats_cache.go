package service

import (
	"context"
	"slices"
	"time"
)

// Display statistics may lag writes by up to five seconds. Search and enforcement
// always read their own data and never use this per-service snapshot.
const statsSnapshotTTL = 5 * time.Second

type countryStat = struct {
	Country string
	Count   int
}
type asnStat = struct {
	ASN    uint
	ASNOrg string
	Count  int
}
type reasonStat = struct {
	Reason string
	Count  int
}

type statsSnapshot struct {
	hour, day, total, active, webhooks, bpm, whitelisted int
	lastBlock                                            int64
	countries                                            []countryStat
	asns                                                 []asnStat
	reasons                                              []reasonStat
	expires                                              time.Time
}

type statsRefresh struct {
	done chan struct{}
	data *statsSnapshot
	err  error
}

// Stats shares display-only aggregates across concurrent requests. Returned
// slices belong to the caller; cached snapshots are immutable after publication.
func (s *IPService) Stats(ctx context.Context) (hour, day, totalEver, activeBlocks int, top []countryStat, topASN []asnStat, topReason []reasonStat, webhooksHour int, lastBlockTs int64, blocksMinute, whitelistCount int, err error) {
	v, err := s.statsSnapshot(ctx)
	if err != nil {
		return 0, 0, 0, 0, nil, nil, nil, 0, 0, 0, 0, err
	}
	return v.hour, v.day, v.total, v.active, slices.Clone(v.countries), slices.Clone(v.asns), slices.Clone(v.reasons), v.webhooks, v.lastBlock, v.bpm, v.whitelisted, nil
}

func (s *IPService) statsSnapshot(ctx context.Context) (*statsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.statsMu.Lock()
	if cached := s.statsCached; cached != nil && time.Now().Before(cached.expires) {
		s.statsMu.Unlock()
		return cached, nil
	}
	if refresh := s.statsRefresh; refresh != nil {
		s.statsMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-refresh.done:
			return refresh.data, refresh.err
		}
	}
	refresh := &statsRefresh{done: make(chan struct{})}
	s.statsRefresh = refresh
	s.statsMu.Unlock()

	// Run in the requesting goroutine, without holding the mutex during I/O.
	v := &statsSnapshot{expires: time.Now().Add(statsSnapshotTTL)}
	var err error
	v.hour, v.day, v.total, v.active, v.countries, v.asns, v.reasons, v.webhooks, v.lastBlock, v.bpm, v.whitelisted, err = s.computeStats(ctx)
	s.statsMu.Lock()
	if err == nil {
		s.statsCached = v
	}
	refresh.data, refresh.err = v, err
	s.statsRefresh = nil
	close(refresh.done)
	s.statsMu.Unlock()
	return v, err
}
