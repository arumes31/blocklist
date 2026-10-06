package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

type testExclusionResolver struct {
	forward func(context.Context, string, string) ([]netip.Addr, error)
	reverse func(context.Context, string) ([]string, error)
}

func (r testExclusionResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r.forward(ctx, network, host)
}

func (r testExclusionResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return r.reverse(ctx, ip)
}

func TestIPService_DNSCoalescesConcurrentLookups(t *testing.T) {
	t.Parallel()
	for _, direction := range []string{"forward", "reverse"} {
		t.Run(direction, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const requests = 64
				var calls atomic.Int32
				release := make(chan struct{})
				ip := netip.MustParseAddr("192.0.2.1")
				svc := &IPService{dnsResolver: testExclusionResolver{
					forward: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
						calls.Add(1)
						if network != "ip" || host != "host.example" {
							t.Error("changed forward lookup arguments")
						}
						deadline, ok := ctx.Deadline()
						if !ok || time.Until(deadline) != 3*time.Second {
							t.Error("changed DNS timeout")
						}
						<-release
						return []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}, nil
					},
					reverse: func(_ context.Context, addr string) ([]string, error) {
						calls.Add(1)
						if addr != ip.String() {
							t.Error("changed reverse lookup address")
						}
						<-release
						return []string{"HOST.Example."}, nil
					},
				}}
				done := make(chan bool, requests)
				for range requests {
					go func() {
						if direction == "forward" {
							_, found := svc.resolveFQDN("host.example")[ip]
							done <- found
						} else {
							names := svc.lookupPTR(ip)
							done <- len(names) == 1 && names[0] == "host.example"
						}
					}()
				}
				synctest.Wait()
				if got := calls.Load(); got != 1 {
					t.Errorf("concurrent cache misses made %d resolver calls, want 1", got)
				}
				close(release)
				for range requests {
					require.True(t, <-done)
				}
				require.EqualValues(t, 1, calls.Load())
			})
		})
	}
}

func TestIPService_DNSIndependentKeysDoNotBlockEachOther(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		svc := &IPService{dnsResolver: testExclusionResolver{
			forward: func(_ context.Context, _, host string) ([]netip.Addr, error) {
				if host == "slow.example" {
					<-release
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			},
		}}
		done := make(chan struct{})
		go func() { svc.resolveFQDN("slow.example"); close(done) }()
		synctest.Wait()
		require.Len(t, svc.resolveFQDN("fast.example"), 1)
		close(release)
		<-done
	})
}

func TestIPService_DNSCacheLifetimes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		ttl   time.Duration
		err   error
		empty bool
	}{
		{name: "positive", ttl: fqdnCacheTTL},
		{name: "empty", ttl: fqdnCacheNegTTL, empty: true},
		{name: "failure", ttl: fqdnCacheNegTTL, empty: true, err: errors.New("DNS unavailable")},
		{name: "partial_failure", ttl: fqdnCacheNegTTL, err: errors.New("partial DNS response")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ip := netip.MustParseAddr("192.0.2.1")
				forwardCalls, reverseCalls := 0, 0
				svc := &IPService{dnsResolver: testExclusionResolver{
					forward: func(context.Context, string, string) ([]netip.Addr, error) {
						forwardCalls++
						if tc.empty {
							return nil, tc.err
						}
						return []netip.Addr{ip}, tc.err
					},
					reverse: func(context.Context, string) ([]string, error) {
						reverseCalls++
						if tc.empty {
							return nil, tc.err
						}
						return []string{"HOST.Example."}, tc.err
					},
				}}
				firstForward, firstReverse := svc.resolveFQDN("host.example"), svc.lookupPTR(ip)
				if tc.empty {
					require.Empty(t, firstForward)
					require.Empty(t, firstReverse)
				} else {
					require.Contains(t, firstForward, ip)
					require.Equal(t, []string{"host.example"}, firstReverse)
				}
				time.Sleep(tc.ttl - time.Nanosecond)
				require.Equal(t, firstForward, svc.resolveFQDN("host.example"))
				require.Equal(t, firstReverse, svc.lookupPTR(ip))
				require.Equal(t, 1, forwardCalls)
				require.Equal(t, 1, reverseCalls)
				time.Sleep(time.Nanosecond)
				svc.resolveFQDN("host.example")
				svc.lookupPTR(ip)
				require.Equal(t, 2, forwardCalls, "expired forward result must be re-resolved")
				require.Equal(t, 2, reverseCalls, "expired reverse result must be re-resolved")
			})
		})
	}
}

func TestIPService_DNSTimeoutAndRetry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc := &IPService{dnsResolver: testExclusionResolver{
			forward: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				calls.Add(1)
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}}
		start := time.Now()
		require.Empty(t, svc.resolveFQDN("timeout.example"))
		require.Equal(t, 3*time.Second, time.Since(start))
		require.Empty(t, svc.resolveFQDN("timeout.example"))
		require.EqualValues(t, 1, calls.Load(), "failed DNS must still use the negative cache")
		time.Sleep(fqdnCacheNegTTL)
		require.Empty(t, svc.resolveFQDN("timeout.example"))
		require.EqualValues(t, 2, calls.Load())
	})
}

func TestIPService_DNSCachePrunesOnlyExpiredEntries(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		ip := netip.MustParseAddr("192.0.2.1")
		svc := &IPService{fqdnCache: make(map[string]fqdnResolution), ptrCache: make(map[netip.Addr]ptrResolution)}
		const expiredCount = 10000
		for i := range expiredCount {
			svc.fqdnCache[fmt.Sprintf("expired-%d.example", i)] = fqdnResolution{expires: now}
			addr := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
			svc.ptrCache[addr] = ptrResolution{names: []string{"expired.example"}, expires: now}
		}
		svc.fqdnCache["live.example"] = fqdnResolution{addrs: map[netip.Addr]struct{}{ip: {}}, expires: now.Add(fqdnCacheTTL)}
		svc.ptrCache[ip] = ptrResolution{names: []string{"live.example"}, expires: now.Add(fqdnCacheTTL)}
		require.Contains(t, svc.resolveFQDN("live.example"), ip)
		require.Equal(t, []string{"live.example"}, svc.lookupPTR(ip))
		require.Len(t, svc.fqdnCache, 1, "one-off hosts must not accumulate forever")
		require.Len(t, svc.ptrCache, 1, "one-off addresses must not accumulate forever")
		require.Equal(t, now.Add(fqdnCacheTTL), svc.fqdnCache["live.example"].expires)
		require.Equal(t, now.Add(fqdnCacheTTL), svc.ptrCache[ip].expires)
		time.Sleep(fqdnCacheTTL)
		_, hit := svc.cachedFQDN("live.example")
		require.False(t, hit)
		_, hit = svc.cachedPTR(ip)
		require.False(t, hit)
		require.Empty(t, svc.fqdnCache)
		require.Empty(t, svc.ptrCache)
	})
}

func TestIPService_DNSForcedRefreshBypassesValidCache(t *testing.T) {
	t.Parallel()
	calls := 0
	svc := &IPService{dnsResolver: testExclusionResolver{
		forward: func(context.Context, string, string) ([]netip.Addr, error) {
			calls++
			return []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(calls)})}, nil
		},
	}}
	require.Contains(t, svc.resolveFQDN("host.example"), netip.MustParseAddr("192.0.2.1"))
	refreshed, err := svc.resolveAndCache("host.example")
	require.NoError(t, err)
	require.Contains(t, refreshed, netip.MustParseAddr("192.0.2.2"))
	require.Equal(t, refreshed, svc.resolveFQDN("host.example"))
	require.Equal(t, 2, calls)
}

func TestIPService_WildcardStillRequiresForwardConfirmation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, ptr, forward string
		want               bool
	}{
		{"confirmed", "HOST.Example.", "192.0.2.1", true},
		{"base_domain", "example.", "192.0.2.1", true},
		{"spoofed_ptr", "host.example.", "192.0.2.2", false},
		{"suffix_confusion", "notexample.", "192.0.2.1", false},
		{"unresolved_forward", "host.example.", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &IPService{dnsResolver: testExclusionResolver{
				forward: func(context.Context, string, string) ([]netip.Addr, error) {
					if tc.forward == "" {
						return nil, errors.New("no address")
					}
					return []netip.Addr{netip.MustParseAddr(tc.forward)}, nil
				},
				reverse: func(context.Context, string) ([]string, error) { return []string{tc.ptr}, nil },
			}}
			for range 2 {
				require.Equal(t, tc.want, svc.matchWildcard("*.example", netip.MustParseAddr("192.0.2.1")))
			}
		})
	}
}

func TestIPService_AddExcludedInvalidatesDNSCache(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	port, err := strconv.Atoi(mr.Port())
	require.NoError(t, err)
	repo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	t.Cleanup(func() { _ = repo.Close() })
	svc := NewIPService(&config.Config{}, repo, nil)
	calls := 0
	svc.dnsResolver = testExclusionResolver{
		forward: func(context.Context, string, string) ([]netip.Addr, error) {
			calls++
			return []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(calls)})}, nil
		},
	}
	require.Contains(t, svc.resolveFQDN("host.example"), netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, svc.AddExcluded(t.Context(), "HOST.Example.", "test", "system", "", false))
	require.True(t, svc.IsExcluded("192.0.2.2"))
	require.False(t, svc.IsExcluded("192.0.2.1"))
	require.Equal(t, 2, calls)
}
