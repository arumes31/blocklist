package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"archive/tar"
	"blocklist/internal/config"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hibiken/asynq"
)

const (
	TypeGeoIPUpdate = "geoip:update"
)

var (
	// validEditionRegex restricts GeoIP edition names to alphanumeric characters and hyphens.
	// This prevents directory traversal and shell injection attacks.
	validEditionRegex = regexp.MustCompile("^[a-zA-Z0-9-]+$")
)

type GeoIPPayload struct {
	Edition string `json:"edition"`
}

func NewGeoIPUpdateTask(edition string) (*asynq.Task, error) {
	if !validEditionRegex.MatchString(edition) {
		return nil, fmt.Errorf("invalid edition: %s", edition)
	}

	payload, err := json.Marshal(GeoIPPayload{Edition: edition})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeGeoIPUpdate, payload, asynq.MaxRetry(3), asynq.Queue("low")), nil
}

type IPService interface {
	ReloadReaders()
}

type GeoIPTaskHandler struct {
	cfg       *config.Config
	ipService IPService
	testURL   string
}

func NewGeoIPTaskHandler(cfg *config.Config, ipService IPService) *GeoIPTaskHandler {
	return &GeoIPTaskHandler{cfg: cfg, ipService: ipService}
}

func (h *GeoIPTaskHandler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var p GeoIPPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}

	// Validate edition string to prevent directory traversal
	if !validEditionRegex.MatchString(p.Edition) {
		return fmt.Errorf("invalid edition: %s: %w", p.Edition, asynq.SkipRetry)
	}

	if err := h.Download(p.Edition); err != nil {
		return err
	}

	if h.ipService != nil {
		h.ipService.ReloadReaders()
	}

	return nil
}

func (h *GeoIPTaskHandler) getDBPath(edition string) string {
	// Defense in depth: ensure filename only contains allowed characters and is just the base
	safeEdition := filepath.Base(edition)
	if !validEditionRegex.MatchString(safeEdition) {
		// This should have been caught earlier, but as a last resort, we'll use a generic name if something went wrong
		// though with our validation it shouldn't happen.
		safeEdition = "unknown"
	}
	filename := safeEdition + ".mmdb"

	// Prefer env-defined path or standard local path
	primaryPath := filepath.Join("/home/blocklist/geoip", filename)

	// Fallback check if running on windows/local dev without specific mounts
	if _, err := os.Stat("/home/blocklist"); err != nil {
		cwd, _ := os.Getwd()
		primaryPath = filepath.Join(cwd, "geoip_data", filename)
	}

	return primaryPath
}

func (h *GeoIPTaskHandler) Download(edition string) error {
	if !validEditionRegex.MatchString(edition) {
		return fmt.Errorf("invalid edition: %s", edition)
	}

	accountID := h.cfg.GeoIPAccountID
	licenseKey := h.cfg.GeoIPLicenseKey

	if accountID == "" || licenseKey == "" {
		return fmt.Errorf("MaxMind credentials missing")
	}

	// Escape edition as well, though our regex already ensures it is safe
	escapedEdition := url.PathEscape(edition)
	downloadURL := h.testURL
	if downloadURL == "" {
		downloadURL = fmt.Sprintf("https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz", escapedEdition)
	} else if strings.Contains(downloadURL, "%s") {
		// Support format string for testing URL construction
		downloadURL = fmt.Sprintf(downloadURL, escapedEdition)
	}

	log.Printf("Asynq: Downloading GeoIP %s", edition)

	client := &http.Client{}
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(accountID, licenseKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if strings.HasSuffix(header.Name, ".mmdb") {
			destPath := h.getDBPath(edition)
			if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
				return err
			}

			outFile, err := os.Create(destPath) // #nosec G304
			if err != nil {
				return err
			}

			// Use LimitReader to prevent decompression bomb (CWE-409)
			// MaxMind GeoLite2 databases are typically < 100MB, so 256MB is a safe upper bound.
			lr := io.LimitReader(tr, 256*1024*1024)
			if _, err := io.Copy(outFile, lr); err != nil {
				_ = outFile.Close()
				return err
			}
			_ = outFile.Close()
			log.Printf("Asynq: Successfully updated GeoIP database: %s", destPath)
			return nil
		}
	}

	return fmt.Errorf("mmdb not found in archive")
}
