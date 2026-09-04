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
	"time"

	"github.com/hibiken/asynq"
	"github.com/oschwald/geoip2-golang"
)

const (
	TypeGeoIPUpdate   = "geoip:update"
	maxGeoIPDBSize    = 256 * 1024 * 1024
	geoIPDownloadTime = 2 * time.Minute
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
	client    *http.Client
	validate  func(string) error
}

func NewGeoIPTaskHandler(cfg *config.Config, ipService IPService) *GeoIPTaskHandler {
	return &GeoIPTaskHandler{
		cfg:       cfg,
		ipService: ipService,
		client: &http.Client{
			Timeout: geoIPDownloadTime,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
					return fmt.Errorf("redirect changed host")
				}
				return nil
			},
		},
		validate: validateGeoIPDatabase,
	}
}

func validateGeoIPDatabase(path string) error {
	reader, err := geoip2.Open(path)
	if err != nil {
		return fmt.Errorf("validate GeoIP database: %w", err)
	}
	return reader.Close()
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

	if err := h.Download(ctx, p.Edition); err != nil {
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

func (h *GeoIPTaskHandler) Download(ctx context.Context, edition string) error {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(accountID, licenseKey)

	resp, err := h.client.Do(req)
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
			if header.Size <= 0 || header.Size > maxGeoIPDBSize {
				return fmt.Errorf("invalid GeoIP database size: %d", header.Size)
			}

			destPath := h.getDBPath(edition)
			if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
				return err
			}

			outFile, err := os.CreateTemp(filepath.Dir(destPath), ".geoip-*.tmp") // #nosec G304 -- fixed, validated destination directory
			if err != nil {
				return err
			}
			tempPath := outFile.Name()
			committed := false
			defer func() {
				_ = outFile.Close()
				if !committed {
					_ = os.Remove(tempPath)
				}
			}()

			if err := outFile.Chmod(0600); err != nil {
				return fmt.Errorf("secure GeoIP temporary file: %w", err)
			}
			written, err := io.CopyN(outFile, tr, header.Size)
			if err != nil || written != header.Size {
				return fmt.Errorf("copy complete GeoIP database: wrote %d of %d bytes: %w", written, header.Size, err)
			}
			if err := outFile.Sync(); err != nil {
				return fmt.Errorf("sync GeoIP database: %w", err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close GeoIP database: %w", err)
			}
			if err := h.validate(tempPath); err != nil {
				return err
			}
			if err := os.Rename(tempPath, destPath); err != nil {
				return fmt.Errorf("activate GeoIP database: %w", err)
			}
			if err := os.Chmod(destPath, 0600); err != nil {
				return fmt.Errorf("secure GeoIP database: %w", err)
			}
			committed = true
			log.Printf("Asynq: Successfully updated GeoIP database: %s", destPath)
			return nil
		}
	}

	return fmt.Errorf("mmdb not found in archive")
}
