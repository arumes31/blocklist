package tasks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"blocklist/internal/config"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestTarGz(t *testing.T, edition string, content string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Simulating a real MaxMind archive which usually has a directory structure
	// e.g., GeoLite2-City_20240101/GeoLite2-City.mmdb
	files := []struct {
		name    string
		content string
	}{
		{name: edition + "_20240101/README.txt", content: "Copyright (c) 2024 MaxMind, Inc."},
		{name: edition + "_20240101/" + edition + ".mmdb", content: content},
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
	expectedContent := "mock mmdb content for success"
	tarData := createTestTarGz(t, edition, expectedContent)

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
	handler.validate = func(string) error { return nil }

	// Ensure cleanup of the downloaded file
	dbPath := handler.getDBPath(edition)
	defer func() { _ = os.Remove(dbPath) }()

	task, err := NewGeoIPUpdateTask(edition)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.NoError(t, err)
	assert.True(t, mockIP.reloadCalled)

	// Verify file exists and has correct content
	content, err := os.ReadFile(dbPath)
	assert.NoError(t, err)
	assert.Equal(t, expectedContent, string(content))
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
	err := handler.Download(context.Background(), "GeoLite2-City")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad status")
}

func TestGeoIPTaskHandler_Download_ValidResponse(t *testing.T) {
	edition := "GeoLite2-City"
	expectedContent := "mock mmdb content for download"
	tarData := createTestTarGz(t, edition, expectedContent)

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
	handler.validate = func(string) error { return nil }

	dbPath := handler.getDBPath(edition)
	defer func() { _ = os.Remove(dbPath) }()

	err := handler.Download(context.Background(), edition)
	assert.NoError(t, err)

	// Verify file exists and has correct content
	content, err := os.ReadFile(dbPath)
	assert.NoError(t, err)
	assert.Equal(t, expectedContent, string(content))
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

	err := handler.Download(context.Background(), edition)
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
			task, err := NewGeoIPUpdateTask(input)
			// Now NewGeoIPUpdateTask will return an error
			if err != nil {
				assert.Contains(t, err.Error(), "invalid edition")
				return
			}

			err = handler.ProcessTask(context.Background(), task)
			assert.Error(t, err, "Should fail for input: %s", input)
			assert.Contains(t, err.Error(), "invalid edition", "Should return invalid edition error for: %s", input)
		})
	}
}

// TestGeoIPTaskHandler_ProcessTask_InvalidEdition exercises the ProcessTask
// handler's own edition validation by manually constructing a task whose payload
// bypasses the NewGeoIPUpdateTask constructor check. This complements
// TestGeoIPTaskHandler_ProcessTask_Traversal, which only reaches the constructor.
func TestGeoIPTaskHandler_ProcessTask_InvalidEdition(t *testing.T) {
	cfg := &config.Config{
		GeoIPAccountID:  "test",
		GeoIPLicenseKey: "test",
	}
	handler := NewGeoIPTaskHandler(cfg, nil)

	payload, err := json.Marshal(GeoIPPayload{Edition: "../../etc/passwd"})
	require.NoError(t, err)
	task := asynq.NewTask(TypeGeoIPUpdate, payload)

	err = handler.ProcessTask(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid edition")
	// Permanent validation failures must not be retried.
	assert.True(t, errors.Is(err, asynq.SkipRetry))
}

func TestGeoIPTaskHandler_Download_URL_Escaping(t *testing.T) {
	cfg := &config.Config{
		GeoIPAccountID:  "test",
		GeoIPLicenseKey: "test",
	}
	handler := NewGeoIPTaskHandler(cfg, nil)

	edition := "../../traversal"
	err := handler.Download(context.Background(), edition)

	// Now it should return an error because it fails validation
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid edition")
}

func TestGeoIPTaskHandler_Download_RejectsOversizedEntry(t *testing.T) {
	var archive bytes.Buffer
	gw := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "GeoLite2-City.mmdb", Size: maxGeoIPDBSize + 1, Mode: 0600}))
	// Deliberately omit the claimed payload. Download must reject the header size
	// before attempting to read or activate this malformed archive.
	require.NoError(t, gw.Close())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive.Bytes())
	}))
	defer server.Close()

	handler := NewGeoIPTaskHandler(&config.Config{GeoIPAccountID: "account", GeoIPLicenseKey: "key"}, nil)
	handler.testURL = server.URL
	err := handler.Download(context.Background(), "GeoLite2-City")
	require.ErrorContains(t, err, "invalid GeoIP database size")
}

func TestGeoIPTaskHandler_Download_RespectsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()

	handler := NewGeoIPTaskHandler(&config.Config{GeoIPAccountID: "account", GeoIPLicenseKey: "key"}, nil)
	handler.testURL = server.URL
	handler.client.Timeout = 20 * time.Millisecond
	err := handler.Download(context.Background(), "GeoLite2-City")
	require.Error(t, err)
}
