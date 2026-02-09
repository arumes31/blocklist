package app

import (
	"blocklist/internal/config"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupIntegration(t *testing.T) (*config.Config, func()) {
	// Setup Redis (miniredis)
	mr, err := miniredis.Run()
	require.NoError(t, err)

	// Setup Postgres (testcontainers)
	ctx := context.Background()
	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("blocklist_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	require.NoError(t, err)

	cleanup := func() {
		mr.Close()
		_ = pgContainer.Terminate(ctx)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// Run migrations
	m, err := migrate.New("file://../../cmd/server/migrations", connStr)
	require.NoError(t, err)
	err = m.Up()
	require.True(t, err == nil || err == migrate.ErrNoChange)

	// Parse Redis host/port
	redisHost, redisPortStr, _ := net.SplitHostPort(mr.Addr())
	redisPort, _ := strconv.Atoi(redisPortStr)

	cfg := &config.Config{
		RedisHost:          redisHost,
		RedisPort:          redisPort,
		RedisPassword:      "",
		RedisDB:            1,
		PostgresURL:        connStr,
		PostgresReadURL:    "",
		AuditLogLimitPerIP: 100,
		BlockedRanges:      "",
		GUIAdmin:           "admin",
		GUIPassword:        "test123",
	}
	return cfg, cleanup
}

func TestBootstrap_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg, cleanup := setupIntegration(t)
	defer cleanup()

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

	// Setup Redis (miniredis) so we pass the Redis check and fail at Postgres
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisHost, redisPortStr, _ := net.SplitHostPort(mr.Addr())
	redisPort, _ := strconv.Atoi(redisPortStr)

	cfg := &config.Config{
		RedisHost:          redisHost,
		RedisPort:          redisPort,
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

	cfg, cleanup := setupIntegration(t)
	defer cleanup()

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
