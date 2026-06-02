package service

import (
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

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
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *ExternalSourceService) RefreshAll(ctx context.Context) {
	sources, err := s.pgRepo.GetActiveExternalSources()
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to fetch active external sources")
		return
	}

	for _, src := range sources {
		if err := s.RefreshSource(ctx, src); err != nil {
			zlog.Error().Err(err).Int("source_id", src.ID).Str("name", src.Name).Msg("Failed to refresh external source")
		}
	}
}

func (s *ExternalSourceService) RefreshSource(ctx context.Context, src models.ExternalSource) error {
	zlog.Info().Int("source_id", src.ID).Str("name", src.Name).Msg("Refreshing external source")

	ips, err := s.fetchAndParse(src)
	if err != nil {
		src.FailureCount++
		src.LastError = err.Error()
		if src.FailureCount >= 6 {
			zlog.Warn().Int("source_id", src.ID).Msg("External source reached max failures, keeping old data but marking as stale")
		}
		_ = s.pgRepo.UpdateExternalSource(src)
		return err
	}

	// Success
	src.FailureCount = 0
	src.LastError = ""
	src.LastRefreshTS = time.Now().UTC().Format(time.RFC3339)
	_ = s.pgRepo.UpdateExternalSource(src)

	// Update excluded list in bulk
	// We prefix the reason to identify these as coming from this source
	reason := fmt.Sprintf("External Source: %s", src.Name)
	for _, ip := range ips {
		// We use a long expiry or no expiry; these will be refreshed anyway
		_ = s.ipService.AddExcluded(ctx, ip, reason, "system", "", false)
	}

	zlog.Info().Int("source_id", src.ID).Int("count", len(ips)).Msg("Successfully refreshed external source")
	return nil
}

func (s *ExternalSourceService) fetchAndParse(src models.ExternalSource) ([]string, error) {
	resp, err := s.client.Get(src.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
	if err := json.Unmarshal(body, &entries); err != nil {
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
	if err := json.Unmarshal(body, &ips); err != nil {
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
