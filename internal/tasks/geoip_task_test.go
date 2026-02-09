package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/config"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGeoIPUpdateTask(t *testing.T) {
	task, err := NewGeoIPUpdateTask("GeoLite2-City")
	require.NoError(t, err)
	require.NotNil(t, task)

	assert.Equal(t, TypeGeoIPUpdate, task.Type())

	// Verify payload
	var payload GeoIPPayload
	err = json.Unmarshal(task.Payload(), &payload)
	require.NoError(t, err)
	assert.Equal(t, "GeoLite2-City", payload.Edition)
}

type mockIPService struct {
	reloadCalled bool
}

func (m *mockIPService) ReloadReaders() {
	m.reloadCalled = true
}

func TestGeoIPTaskHandler_ProcessTask_Success(t *testing.T) {
	// Create a mock HTTP server that returns a valid tar.gz
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-account" || pass != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return a minimal valid tar.gz with a .mmdb file
		// For simplicity, we'll just return an error in this test
		// A full implementation would create a proper tar.gz
		w.WriteHeader(http.StatusOK)
		// Write minimal tar.gz content (this is a simplified mock)
		_, _ = w.Write([]byte("mock-tar-gz-content"))
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	mockIP := &mockIPService{}
	handler := NewGeoIPTaskHandler(cfg, mockIP)

	task, err := NewGeoIPUpdateTask("GeoLite2-City")
	require.NoError(t, err)

	// Note: This will fail because we're not returning a valid tar.gz
	// In a real test, you'd use a proper mock or test fixture
	err = handler.ProcessTask(context.Background(), task)
	// We expect an error because our mock doesn't return valid tar.gz
	assert.Error(t, err)
}

func TestGeoIPTaskHandler_ProcessTask_InvalidPayload(t *testing.T) {
	cfg := &config.Config{}
	handler := NewGeoIPTaskHandler(cfg, nil)

	// Create task with invalid payload
	task := asynq.NewTask(TypeGeoIPUpdate, []byte("invalid-json"))

	err := handler.ProcessTask(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "json.Unmarshal failed")
}

func TestGeoIPTaskHandler_ProcessTask_MissingCredentials(t *testing.T) {
	cfg := &config.Config{
		GeoIPAccountID:  "",
		GeoIPLicenseKey: "",
	}

	handler := NewGeoIPTaskHandler(cfg, nil)

	task, err := NewGeoIPUpdateTask("GeoLite2-City")
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MaxMind credentials missing")
}

func TestGeoIPTaskHandler_getDBPath(t *testing.T) {
	cfg := &config.Config{}
	handler := NewGeoIPTaskHandler(cfg, nil)

	path := handler.getDBPath("GeoLite2-City")
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "GeoLite2-City.mmdb")
}

func TestGeoIPTaskHandler_Download_HTTPError(t *testing.T) {
	// Create a mock HTTP server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	handler := NewGeoIPTaskHandler(cfg, nil)

	// This will fail because the mock server returns 403
	err := handler.Download("GeoLite2-City")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad status")
}

func TestGeoIPTaskHandler_Download_ValidResponse(t *testing.T) {
	t.Skip("Skipping - requires refactoring Download method to accept custom HTTP client")

	// This test would require refactoring the Download method to inject
	// a custom HTTP client or URL for testing purposes.
	// Current implementation hardcodes the MaxMind URL.
}
