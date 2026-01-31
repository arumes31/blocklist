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

func (s *GeoIPService) getDBPath() string {
	path := "/home/blocklist/geoip/GeoLite2-City.mmdb"
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "/tmp/GeoLite2-City.mmdb"
	}
	// Check if writable
	testFile := filepath.Join(dir, ".permtest")
	f, err := os.Create(testFile)
	if err != nil {
		return "/tmp/GeoLite2-City.mmdb"
	}
	f.Close()
	_ = os.Remove(testFile)
	return path
}

func (s *GeoIPService) Start() {
	dbPath := s.getDBPath()
	
	// 1. Initial Check
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Printf("GeoIP database missing at %s. Starting initial download...", dbPath)
		if err := s.Download(); err != nil {
			log.Printf("Failed to download GeoIP database: %v", err)
		}
	}

	// 2. Schedule Update every 72 hours
	ticker := time.NewTicker(72 * time.Hour)
	go func() {
		for range ticker.C {
			log.Println("Starting scheduled GeoIP database update...")
			if err := s.Download(); err != nil {
				log.Printf("Failed to update GeoIP database: %v", err)
			}
		}
	}()
}

func (s *GeoIPService) Download() error {
	accountID := s.cfg.GeoIPAccountID
	licenseKey := s.cfg.GeoIPLicenseKey

	if accountID == "" || licenseKey == "" || licenseKey == "XXXXXXXX---SECRET_LICENSEKEY----" {
		return fmt.Errorf("GEOIPUPDATE_ACCOUNT_ID or GEOIPUPDATE_LICENSE_KEY not set")
	}

	// MaxMind modern permalink URL for GeoLite2-City
	url := "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
	
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
			destPath := s.getDBPath()
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