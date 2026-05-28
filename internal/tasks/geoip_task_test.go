package tasks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func createTestTarGz(t *testing.T, filename string, content []byte) []byte {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	header := &tar.Header{
		Name: filename,
		Mode: 0600,
		Size: int64(len(content)),
	}
	err := tw.WriteHeader(header)
	require.NoError(t, err)

	_, err = tw.Write(content)
	require.NoError(t, err)

	err = tw.Close()
	require.NoError(t, err)

	err = gzw.Close()
	require.NoError(t, err)

	return buf.Bytes()
}

func TestGeoIPTaskHandler_ProcessTask_Success(t *testing.T) {
	edition := "GeoLite2-City"
	mockTarContent := createTestTarGz(t, "GeoLite2-City_20231010/GeoLite2-City.mmdb", []byte("fake-mmdb-content"))

	// Create a mock HTTP server that returns a valid tar.gz
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-account" || pass != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check URL
		expectedPath := fmt.Sprintf("/%s/download", edition)
		if r.URL.Path != expectedPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockTarContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	tempDir := t.TempDir()
	mockIP := &mockIPService{}
	handler := NewGeoIPTaskHandler(cfg, mockIP)
	handler.baseURL = server.URL
	handler.dataDir = tempDir

	task, err := NewGeoIPUpdateTask(edition)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	assert.True(t, mockIP.reloadCalled)

	// Verify file was created
	dbPath := filepath.Join(tempDir, edition+".mmdb")
	_, err = os.Stat(dbPath)
	assert.NoError(t, err)

	content, err := os.ReadFile(dbPath)
	assert.NoError(t, err)
	assert.Equal(t, []byte("fake-mmdb-content"), content)
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

	// Test with dataDir
	handler.dataDir = "/tmp/geoip"
	path = handler.getDBPath("GeoLite2-City")
	assert.Equal(t, "/tmp/geoip/GeoLite2-City.mmdb", path)
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
	handler.baseURL = server.URL

	// This will fail because the mock server returns 403
	err := handler.Download("GeoLite2-City")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad status")
}

func TestGeoIPTaskHandler_Download_ValidResponse(t *testing.T) {
	edition := "GeoLite2-City"
	mockTarContent := createTestTarGz(t, "GeoLite2-City.mmdb", []byte("fake-mmdb-content"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockTarContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	tempDir := t.TempDir()
	handler := NewGeoIPTaskHandler(cfg, nil)
	handler.baseURL = server.URL
	handler.dataDir = tempDir

	err := handler.Download(edition)
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, edition+".mmdb")
	content, err := os.ReadFile(dbPath)
	assert.NoError(t, err)
	assert.Equal(t, []byte("fake-mmdb-content"), content)
}
