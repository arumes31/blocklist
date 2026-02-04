package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hibiken/asynq"
	"blocklist/internal/config"
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	TypeGeoIPUpdate = "geoip:update"
)

type GeoIPPayload struct {
	Edition string `json:"edition"`
}

func NewGeoIPUpdateTask(edition string) (*asynq.Task, error) {
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
}

func NewGeoIPTaskHandler(cfg *config.Config, ipService IPService) *GeoIPTaskHandler {
	return &GeoIPTaskHandler{cfg: cfg, ipService: ipService}
}

func (h *GeoIPTaskHandler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var p GeoIPPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
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
	filename := edition + ".mmdb"
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
	accountID := h.cfg.GeoIPAccountID
	licenseKey := h.cfg.GeoIPLicenseKey

	if accountID == "" || licenseKey == "" {
		return fmt.Errorf("MaxMind credentials missing")
	}

	url := fmt.Sprintf("https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz", edition)
	log.Printf("Asynq: Downloading GeoIP %s", edition)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(accountID, licenseKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF { break }
		if err != nil { return err }

		if strings.HasSuffix(header.Name, ".mmdb") {
			destPath := h.getDBPath(edition)
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return err
			}

			outFile, err := os.Create(destPath)
			if err != nil { return err }
			
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
			log.Printf("Asynq: Successfully updated GeoIP database: %s", destPath)
			return nil
		}
	}

	return fmt.Errorf("mmdb not found in archive")
}
