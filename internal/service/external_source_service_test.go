package service

import (
	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestExternalSourceService_RefreshSource(t *testing.T) {
	// Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	redisRepo := repository.NewRedisRepository(host, port, "", 0)

	ipService := NewIPService(&config.Config{}, redisRepo, nil)
	extService := NewExternalSourceService(nil, ipService)

	// Mock server to return IP lists
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/plaintext":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("192.168.1.5\n# comment\n10.0.0.0/24\n"))
		case "/json":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`["172.16.0.1", "172.16.0.0/16"]`))
		case "/ms365":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"ips": ["192.0.2.1", "192.0.2.0/24"]}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	t.Run("Plaintext format", func(t *testing.T) {
		mr.FlushAll()
		src := models.ExternalSource{
			ID:         1,
			Name:       "Test Plaintext",
			URL:        server.URL + "/plaintext",
			SourceType: "plaintext",
		}

		err := extService.RefreshSource(ctx, src)
		if err != nil {
			t.Fatalf("RefreshSource failed: %v", err)
		}

		// Retrieve excluded entries
		entries, err := redisRepo.GetExcludedEntries()
		if err != nil {
			t.Fatalf("GetExcludedEntries failed: %v", err)
		}

		if len(entries) != 2 {
			t.Fatalf("expected 2 excluded entries, got %d", len(entries))
		}

		for _, val := range []string{"192.168.1.5", "10.0.0.0/24"} {
			entry, ok := entries[val]
			if !ok {
				t.Errorf("expected %s to be excluded", val)
				continue
			}
			if entry.ExpiresAt == "" {
				t.Errorf("expected expires_at to be set")
				continue
			}
			expTime, err := time.Parse(time.RFC3339, entry.ExpiresAt)
			if err != nil {
				t.Errorf("failed to parse expires_at %q: %v", entry.ExpiresAt, err)
				continue
			}
			expectedExp := time.Now().Add(24 * time.Hour)
			diff := expTime.Sub(expectedExp)
			if diff < -5*time.Second || diff > 5*time.Second {
				t.Errorf("expires_at %v is not around 24h in future (%v)", expTime, expectedExp)
			}
			if entry.Reason != "External Source: Test Plaintext" {
				t.Errorf("unexpected reason: %q", entry.Reason)
			}
		}
	})

	t.Run("JSON format", func(t *testing.T) {
		mr.FlushAll()
		src := models.ExternalSource{
			ID:         2,
			Name:       "Test JSON",
			URL:        server.URL + "/json",
			SourceType: "json_cidr",
		}

		err := extService.RefreshSource(ctx, src)
		if err != nil {
			t.Fatalf("RefreshSource failed: %v", err)
		}

		entries, err := redisRepo.GetExcludedEntries()
		if err != nil {
			t.Fatalf("GetExcludedEntries failed: %v", err)
		}

		if len(entries) != 2 {
			t.Fatalf("expected 2 excluded entries, got %d", len(entries))
		}
		for _, val := range []string{"172.16.0.1", "172.16.0.0/16"} {
			entry, ok := entries[val]
			if !ok {
				t.Errorf("expected %s to be excluded", val)
				continue
			}
			if entry.ExpiresAt == "" {
				t.Errorf("expected expires_at to be set")
			}
		}
	})

	t.Run("MS365 format", func(t *testing.T) {
		mr.FlushAll()
		src := models.ExternalSource{
			ID:         3,
			Name:       "Test MS365",
			URL:        server.URL + "/ms365",
			SourceType: "microsoft_365",
		}

		err := extService.RefreshSource(ctx, src)
		if err != nil {
			t.Fatalf("RefreshSource failed: %v", err)
		}

		entries, err := redisRepo.GetExcludedEntries()
		if err != nil {
			t.Fatalf("GetExcludedEntries failed: %v", err)
		}

		if len(entries) != 2 {
			t.Fatalf("expected 2 excluded entries, got %d", len(entries))
		}
		for _, val := range []string{"192.0.2.1", "192.0.2.0/24"} {
			entry, ok := entries[val]
			if !ok {
				t.Errorf("expected %s to be excluded", val)
				continue
			}
			if entry.ExpiresAt == "" {
				t.Errorf("expected expires_at to be set")
			}
		}
	})
}
