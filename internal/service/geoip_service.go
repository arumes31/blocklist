package service

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"blocklist/internal/config"
)

type GeoIPService struct {
	cfg *config.Config
}

func NewGeoIPService(cfg *config.Config) *GeoIPService {
	return &GeoIPService{cfg: cfg}
}

func (s *GeoIPService) Start() {
	// 1. Initial Check for both City and ASN
	for _, edition := range []string{"GeoLite2-City", "GeoLite2-ASN"} {
		dbPath := s.getDBPath(edition)
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			log.Printf("GeoIP %s database missing at %s. Starting initial download...", edition, dbPath)
			if err := s.Download(edition); err != nil {
				log.Printf("Failed to download %s database: %v", edition, err)
			}
		}
	}

	// 2. Schedule Update every 72 hours
	ticker := time.NewTicker(72 * time.Hour)
	go func() {
		for range ticker.C {
			log.Printf("Starting scheduled GeoIP database update...")
			for _, edition := range []string{"GeoLite2-City", "GeoLite2-ASN"} {
				if err := s.Download(edition); err != nil {
					log.Printf("Failed to update %s database: %v", edition, err)
				}
			}
		}
	}()
}

func (s *GeoIPService) getDBPath(edition string) string {
	filename := edition + ".mmdb"
	primaryPath := filepath.Join("/home/blocklist/geoip", filename)
	dir := filepath.Dir(primaryPath)
	
	// Try to ensure primary directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Warning: Failed to create primary GeoIP directory %s: %v. Falling back to /tmp.", dir, err)
		return filepath.Join("/tmp", filename)
	}
	
	// Test if primary directory is writable
	testFile := filepath.Join(dir, ".permtest")
	f, err := os.Create(testFile)
	if err != nil {
		log.Printf("Warning: Primary GeoIP directory %s is not writable: %v. Falling back to /tmp. (Check volume permissions)", dir, err)
		return filepath.Join("/tmp", filename)
	}
	f.Close()
	_ = os.Remove(testFile)
	
	return primaryPath
}

func (s *GeoIPService) Download(edition string) error {
	accountID := s.cfg.GeoIPAccountID
	licenseKey := s.cfg.GeoIPLicenseKey

	if accountID == "" || licenseKey == "" || licenseKey == "XXXXXXXX---SECRET_LICENSEKEY----" {
		return fmt.Errorf("GEOIPUPDATE_ACCOUNT_ID or GEOIPUPDATE_LICENSE_KEY not set")
	}

	url := fmt.Sprintf("https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz", edition)
	
	log.Printf("Attempting GeoIP download from %s using AccountID: %s", url, accountID)
	
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

	// Extract tar.gz in memory or temp file
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzr.Close()

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
			destPath := s.getDBPath(edition)
			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return err
			}

			outFile, err := os.Create(destPath)
			if err != nil {
				return err
			}
			
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
			log.Printf("Successfully updated GeoIP database: %s", destPath)
			return nil
		}
	}

	return fmt.Errorf("GeoLite2-City.mmdb not found in archive")
}