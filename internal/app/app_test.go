package app

import (
	"blocklist/internal/config"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrap_Success(t *testing.T) {
	// This test requires actual Redis and Postgres instances
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := &config.Config{
		RedisHost:          "localhost",
		RedisPort:          6379,
		RedisPassword:      "",
		RedisDB:            1, // Use different DB for tests
		PostgresURL:        "postgres://postgres:postgres@localhost:5432/blocklist_test?sslmode=disable",
		PostgresReadURL:    "",
		AuditLogLimitPerIP: 100,
		BlockedRanges:      "",
		GUIAdmin:           "admin",
		GUIPassword:        "test123",
	}

	app, err := Bootstrap(cfg)
	require.NoError(t, err, "Bootstrap should succeed with valid config")
	require.NotNil(t, app, "App should not be nil")

	// Verify all services are initialized
	assert.NotNil(t, app.Config)
	assert.NotNil(t, app.RedisRepo)
	assert.NotNil(t, app.PgRepo)
	assert.NotNil(t, app.AuthService)
	assert.NotNil(t, app.IPService)
	assert.NotNil(t, app.WebhookService)
	assert.NotNil(t, app.GeoUpdater)
	assert.NotNil(t, app.Scheduler)

	// Cleanup
	app.Close()
}

func TestBootstrap_RedisFailure(t *testing.T) {
	cfg := &config.Config{
		RedisHost:          "invalid-host-that-does-not-exist",
		RedisPort:          6379,
		RedisPassword:      "",
		RedisDB:            0,
		PostgresURL:        "postgres://postgres:postgres@localhost:5432/blocklist_test?sslmode=disable",
		AuditLogLimitPerIP: 100,
	}

	app, err := Bootstrap(cfg)
	assert.Error(t, err, "Bootstrap should fail with invalid Redis host")
	assert.Nil(t, app, "App should be nil on failure")
	assert.Contains(t, err.Error(), "failed to connect to Redis")
}

func TestBootstrap_PostgresFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := &config.Config{
		RedisHost:          "localhost",
		RedisPort:          6379,
		RedisPassword:      "",
		RedisDB:            1,
		PostgresURL:        "postgres://invalid:invalid@invalid-host:5432/invalid?sslmode=disable",
		AuditLogLimitPerIP: 100,
	}

	app, err := Bootstrap(cfg)
	assert.Error(t, err, "Bootstrap should fail with invalid Postgres URL")
	assert.Nil(t, app, "App should be nil on failure")
	assert.Contains(t, err.Error(), "failed to connect to Postgres")
}

func TestClose(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := &config.Config{
		RedisHost:          "localhost",
		RedisPort:          6379,
		RedisPassword:      "",
		RedisDB:            1,
		PostgresURL:        "postgres://postgres:postgres@localhost:5432/blocklist_test?sslmode=disable",
		AuditLogLimitPerIP: 100,
		GUIAdmin:           "admin",
		GUIPassword:        "test123",
	}

	app, err := Bootstrap(cfg)
	require.NoError(t, err)
	require.NotNil(t, app)

	// Close should not panic
	assert.NotPanics(t, func() {
		app.Close()
	})

	// Calling Close again should also not panic
	assert.NotPanics(t, func() {
		app.Close()
	})
}

func TestClose_NilServices(t *testing.T) {
	// Test that Close handles nil services gracefully
	app := &App{
		WebhookService: nil,
		GeoUpdater:     nil,
	}

	assert.NotPanics(t, func() {
		app.Close()
	})
}
