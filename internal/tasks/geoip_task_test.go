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
	"testing"

	"blocklist/internal/config"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestTarGz(t *testing.T, filename string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Simulating a real MaxMind archive which usually has a directory structure
	// e.g., GeoLite2-City_20240101/GeoLite2-City.mmdb
	files := []struct {
		name    string
		content string
	}{
		{name: "GeoLite2-City_20240101/README.txt", content: "Copyright (c) 2024 MaxMind, Inc."},
		{name: "GeoLite2-City_20240101/" + filename, content: "mock mmdb content"},
	}

	for _, f := range files {
		header := &tar.Header{
			Name: f.name,
			Size: int64(len(f.content)),
			Mode: 0600,
		}

		err := tw.WriteHeader(header)
		require.NoError(t, err)

		_, err = tw.Write([]byte(f.content))
		require.NoError(t, err)
	}

	err := tw.Close()
	require.NoError(t, err)

	err = gw.Close()
	require.NoError(t, err)

	return buf.Bytes()
}

func createEmptyTarGz(t *testing.T) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{
		Name: "README.txt",
		Size: 10,
		Mode: 0600,
	}
	err := tw.WriteHeader(header)
	require.NoError(t, err)
	_, _ = tw.Write([]byte("1234567890"))

	err = tw.Close()
	require.NoError(t, err)
	err = gw.Close()
	require.NoError(t, err)
	return buf.Bytes()
}

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
	edition := "GeoLite2-City"
	tarData := createTestTarGz(t, edition+".mmdb")

	// Create a mock HTTP server that returns a valid tar.gz
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-account" || pass != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarData)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	mockIP := &mockIPService{}
	handler := NewGeoIPTaskHandler(cfg, mockIP)
	handler.testURL = server.URL

	// Ensure cleanup of the downloaded file
	dbPath := handler.getDBPath(edition)
	defer func() { _ = os.Remove(dbPath) }()

	task, err := NewGeoIPUpdateTask(edition)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.NoError(t, err)
	assert.True(t, mockIP.reloadCalled)

	// Verify file exists
	_, err = os.Stat(dbPath)
	assert.NoError(t, err)
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
	handler.testURL = server.URL

	// This will fail because the mock server returns 403
	err := handler.Download("GeoLite2-City")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad status")
}

func TestGeoIPTaskHandler_Download_ValidResponse(t *testing.T) {
	edition := "GeoLite2-City"
	tarData := createTestTarGz(t, edition+".mmdb")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarData)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	handler := NewGeoIPTaskHandler(cfg, nil)
	handler.testURL = server.URL

	dbPath := handler.getDBPath(edition)
	defer func() { _ = os.Remove(dbPath) }()

	err := handler.Download(edition)
	assert.NoError(t, err)

	_, err = os.Stat(dbPath)
	assert.NoError(t, err)
}

func TestGeoIPTaskHandler_Download_NoMMDB(t *testing.T) {
	edition := "GeoLite2-City"
	tarData := createEmptyTarGz(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarData)
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test-account",
		GeoIPLicenseKey: "test-key",
	}

	handler := NewGeoIPTaskHandler(cfg, nil)
	handler.testURL = server.URL

	err := handler.Download(edition)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mmdb not found in archive")
}

func TestGeoIPTaskHandler_ProcessTask_Traversal(t *testing.T) {
	cfg := &config.Config{
		GeoIPAccountID:  "test",
		GeoIPLicenseKey: "test",
	}
	handler := NewGeoIPTaskHandler(cfg, nil)

	traversalInputs := []string{
		"../../etc/passwd",
		"..\\..\\etc\\passwd",
		"GeoLite2-City/../../etc/passwd",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
	}

	for _, input := range traversalInputs {
		t.Run(input, func(t *testing.T) {
			task, _ := NewGeoIPUpdateTask(input)
			err := handler.ProcessTask(context.Background(), task)
			assert.Error(t, err, "Should fail for input: %s", input)
			assert.Contains(t, err.Error(), "invalid edition", "Should return invalid edition error for: %s", input)
		})
	}
}

func TestGeoIPTaskHandler_Download_URL_Escaping(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.RawPath
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(createTestTarGz(t, "test.mmdb"))
	}))
	defer server.Close()

	cfg := &config.Config{
		GeoIPAccountID:  "test",
		GeoIPLicenseKey: "test",
	}
	handler := NewGeoIPTaskHandler(cfg, nil)
	// We expect the fix to use this as a format string
	handler.testURL = server.URL + "/databases/%s/download"

	edition := "../../traversal"
	_ = handler.Download(edition)

	// If properly escaped, it should contain %2F
	assert.Contains(t, capturedPath, "..%2F..%2Ftraversal", "The edition parameter in the URL should be path-escaped")
}
