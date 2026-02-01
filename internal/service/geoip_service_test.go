package service

import (
	"testing"

	"blocklist/internal/config"
)

func TestGeoIPService_Download_NoConfig(t *testing.T) {
	svc := NewGeoIPService(&config.Config{})
	err := svc.Download("GeoLite2-City")
	if err == nil {
		t.Error("expected error when no config is provided")
	}
}
