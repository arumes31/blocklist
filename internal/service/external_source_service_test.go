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

// newTestClient returns a client that dials the given test server regardless of
// the request's host, so tests can use public-looking URLs that pass the SSRF
// check while still reaching a loopback listener.
func newTestClient(server *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, server.Listener.Addr().String())
			},
		},
	}
}

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

	// Sources are addressed by a public-looking hostname so they survive the SSRF
	// URL check, while the injected client dials the loopback test server.
	extService := NewExternalSourceServiceWithClient(nil, ipService, newTestClient(server))
	const sourceHost = "http://example.com"

	ctx := context.Background()

	t.Run("Plaintext format", func(t *testing.T) {
		mr.FlushAll()
		src := models.ExternalSource{
			ID:         1,
			Name:       "Test Plaintext",
			URL:        sourceHost + "/plaintext",
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
			URL:        sourceHost + "/json",
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

	t.Run("Internal URL is refused at refresh time", func(t *testing.T) {
		mr.FlushAll()
		// A source row pointing at internal address space must be refused even
		// though it is already stored, and must not populate the excluded list.
		src := models.ExternalSource{
			ID:         4,
			Name:       "Rebound Source",
			URL:        "http://127.0.0.1/plaintext",
			SourceType: "plaintext",
		}

		if err := extService.RefreshSource(ctx, src); err == nil {
			t.Fatal("expected RefreshSource to reject an internal URL")
		}

		entries, err := redisRepo.GetExcludedEntries()
		if err != nil {
			t.Fatalf("GetExcludedEntries failed: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("expected no excluded entries, got %d", len(entries))
		}
	})

	t.Run("MS365 format", func(t *testing.T) {
		mr.FlushAll()
		src := models.ExternalSource{
			ID:         3,
			Name:       "Test MS365",
			URL:        sourceHost + "/ms365",
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
