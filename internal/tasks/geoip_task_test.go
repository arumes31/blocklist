package tasks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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

func TestGeoIPTaskHandler_ProcessTask_Success(t *testing.T) {
	tempDir := t.TempDir()
	mockTarGz := createMockTarGz(t, "GeoLite2-City_20230101/GeoLite2-City.mmdb", "fake-mmdb-content")

	// Create a mock HTTP server that returns a valid tar.gz
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-account" || pass != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockTarGz)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	mockIP := &mockIPService{}
	handler := NewGeoIPTaskHandler(cfg, mockIP)
	handler.downloadURL = server.URL + "/%s"
	handler.dbPathFunc = func(edition string) string {
		return filepath.Join(tempDir, edition+".mmdb")
	}

	task, err := NewGeoIPUpdateTask("GeoLite2-City")
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.NoError(t, err)

	assert.True(t, mockIP.reloadCalled)

	// Verify file was created
	dbPath := handler.getDBPath("GeoLite2-City")
	_, err = os.Stat(dbPath)
	assert.NoError(t, err)

	content, err := os.ReadFile(dbPath)
	assert.NoError(t, err)
	assert.Equal(t, "fake-mmdb-content", string(content))
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
	tempDir := t.TempDir()
	mockTarGz := createMockTarGz(t, "GeoLite2-City.mmdb", "fake-mmdb-content-2")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockTarGz)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	handler := NewGeoIPTaskHandler(cfg, nil)
	handler.downloadURL = server.URL + "/%s"
	handler.dbPathFunc = func(edition string) string {
		return filepath.Join(tempDir, edition+".mmdb")
	}

	err := handler.Download("GeoLite2-City")
	assert.NoError(t, err)

	dbPath := handler.getDBPath("GeoLite2-City")
	content, err := os.ReadFile(dbPath)
	assert.NoError(t, err)
	assert.Equal(t, "fake-mmdb-content-2", string(content))
}

func createMockTarGz(t *testing.T, filename string, content string) []byte {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	header := &tar.Header{
		Name: filename,
		Size: int64(len(content)),
		Mode: 0600,
	}
	err := tw.WriteHeader(header)
	require.NoError(t, err)

	_, err = tw.Write([]byte(content))
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gzw.Close())

	return buf.Bytes()
}
