package service

import (
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/security"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	zlog "github.com/rs/zerolog/log"
)

type ExternalSourceService struct {
	pgRepo    *repository.PostgresRepository
	ipService *IPService
	client    *http.Client
}

func NewExternalSourceService(pgRepo *repository.PostgresRepository, ipService *IPService) *ExternalSourceService {
	return &ExternalSourceService{
		pgRepo:    pgRepo,
		ipService: ipService,
		client:    newGuardedClient(),
	}
}

// maxExternalSourceRedirects bounds redirect chasing so a hostile endpoint
// cannot keep us looping.
const maxExternalSourceRedirects = 5

// newGuardedClient builds the HTTP client used to fetch operator-configured
// source URLs. Validating the URL when it is added is not sufficient on its own:
// the host may resolve to a public address at validation time and to an internal
// one at fetch time (DNS rebinding), and a public URL may redirect inward.
//
// SafeSocketControl is therefore the authoritative check. It runs after DNS
// resolution on every connection attempt, including those made while following
// redirects, so it sees the address actually being dialed.
func newGuardedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		Control:   security.SafeSocketControl,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxExternalSourceRedirects {
				return fmt.Errorf("stopped after %d redirects", maxExternalSourceRedirects)
			}
			return security.IsSafeURL(req.URL.String())
		},
	}
}

func (s *ExternalSourceService) RefreshAll(ctx context.Context) error {
	sources, err := s.pgRepo.GetActiveExternalSources()
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to fetch active external sources")
		return fmt.Errorf("fetch active external sources: %w", err)
	}

	var failures int
	for _, src := range sources {
		if err := s.RefreshSource(ctx, src); err != nil {
			failures++
			zlog.Error().Err(err).Int("source_id", src.ID).Str("name", src.Name).Msg("Failed to refresh external source")
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d external sources failed to refresh", failures, len(sources))
	}
	return nil
}

func (s *ExternalSourceService) RefreshSource(ctx context.Context, src models.ExternalSource) error {
	zlog.Info().Int("source_id", src.ID).Str("name", src.Name).Msg("Refreshing external source")

	ips, err := s.fetchAndParse(ctx, src)
	if err != nil {
		src.FailureCount++
		src.LastError = err.Error()
		if src.FailureCount >= 6 {
			zlog.Warn().Int("source_id", src.ID).Msg("External source reached max failures, keeping old data but marking as stale")
		}
		if s.pgRepo != nil {
			_ = s.pgRepo.UpdateExternalSource(src)
		}
		return err
	}

	// Success
	src.FailureCount = 0
	src.LastError = ""
	src.LastRefreshTS = time.Now().UTC().Format(time.RFC3339)
	if s.pgRepo != nil {
		_ = s.pgRepo.UpdateExternalSource(src)
	}

	// Update excluded list in bulk
	// We prefix the reason to identify these as coming from this source
	reason := fmt.Sprintf("External Source: %s", src.Name)
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	excluded := make([]string, 0, len(ips))
	for _, ip := range ips {
		if err := s.ipService.AddExcluded(ctx, ip, reason, "system", expiresAt, false); err != nil {
			zlog.Warn().Err(err).Int("source_id", src.ID).Str("ip", ip).Msg("External source: failed to add excluded entry")
			continue
		}
		excluded = append(excluded, ip)
	}
	// Only audit-log the entries that were actually persisted, so the log reflects
	// the real exclusion state rather than the full input set.
	if s.pgRepo != nil && len(excluded) > 0 {
		_ = s.pgRepo.BulkLogAction("system", "EXCLUDE", excluded, reason)
	}

	zlog.Info().Int("source_id", src.ID).Int("count", len(excluded)).Msg("Successfully refreshed external source")
	return nil
}

// maxExternalSourceBytes caps how much of a remote source body we will read into
// memory, bounding resource use on a hostile or misbehaving endpoint.
const maxExternalSourceBytes = 32 * 1024 * 1024 // 32 MiB

func (s *ExternalSourceService) fetchAndParse(ctx context.Context, src models.ExternalSource) ([]string, error) {
	// Re-check on every refresh rather than trusting the stored value: rows may
	// predate input validation, and a source that was safe when added can be
	// repointed at internal address space later.
	if err := security.IsSafeURL(src.URL); err != nil {
		return nil, fmt.Errorf("unsafe external source URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxExternalSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxExternalSourceBytes {
		return nil, fmt.Errorf("external source exceeds %d-byte limit", maxExternalSourceBytes)
	}

	switch src.SourceType {
	case "microsoft_365":
		return s.parseMicrosoft365(body)
	case "json_cidr":
		return s.parseJSONCIDR(body)
	default:
		return s.parsePlaintext(body)
	}
}

func (s *ExternalSourceService) parseMicrosoft365(body []byte) ([]string, error) {
	// Microsoft 365 endpoint returns JSON with 'ips' arrays
	type msEntry struct {
		IPs []string `json:"ips"`
	}
	var entries []msEntry
	if err := sonic.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var results []string
	for _, e := range entries {
		results = append(results, e.IPs...)
	}
	return results, nil
}

func (s *ExternalSourceService) parseJSONCIDR(body []byte) ([]string, error) {
	var ips []string
	if err := sonic.Unmarshal(body, &ips); err != nil {
		return nil, err
	}
	return ips, nil
}

func (s *ExternalSourceService) parsePlaintext(body []byte) ([]string, error) {
	lines := strings.Split(string(body), "\n")
	var results []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Basic validation: is it a valid IP or CIDR?
		if _, err := netip.ParseAddr(line); err == nil {
			results = append(results, line)
		} else if _, err := netip.ParsePrefix(line); err == nil {
			results = append(results, line)
		}
	}
	return results, nil
}
