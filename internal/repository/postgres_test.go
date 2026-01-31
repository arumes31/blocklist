package repository

import (
	"context"
	"testing"
	"time"

	"blocklist/internal/models"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestPostgresRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Start Postgres container
	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("blocklist"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}
	defer func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %s", err)
	}

	// Run migrations
	// Note: We need the absolute path to migrations
	m, err := migrate.New("file://../../cmd/server/migrations", connStr)
	if err != nil {
		t.Fatalf("failed to init migrate: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to run migrations: %v", err)
	}

	repo, err := NewPostgresRepository(connStr)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}

	t.Run("AdminOperations", func(t *testing.T) {
		admin := models.AdminAccount{
			Username:     "admin_test",
			PasswordHash: "hashed_pass",
			Token:        "totp_secret",
			Role:         "admin",
		}

		err := repo.CreateAdmin(admin)
		if err != nil {
			t.Errorf("CreateAdmin failed: %v", err)
		}

		got, err := repo.GetAdmin(admin.Username)
		if err != nil {
			t.Errorf("GetAdmin failed: %v", err)
		}
		if got.Role != "admin" {
			t.Errorf("expected role admin, got %s", got.Role)
		}

		admins, _ := repo.GetAllAdmins()
		if len(admins) == 0 {
			t.Error("GetAllAdmins returned empty list")
		}
	})

	t.Run("PersistentBlocks", func(t *testing.T) {
		ip := "10.10.10.10"
		entry := models.IPEntry{
			Timestamp:   "2026-01-31 18:00:00 UTC",
			Reason:      "persistent-test",
			AddedBy:     "manual",
			Geolocation: &models.GeoData{Country: "DE", City: "Berlin"},
		}

		err := repo.CreatePersistentBlock(ip, entry)
		if err != nil {
			t.Errorf("CreatePersistentBlock failed: %v", err)
		}

		blocks, err := repo.GetPersistentBlocks()
		if err != nil {
			t.Errorf("GetPersistentBlocks failed: %v", err)
		}
		if _, ok := blocks[ip]; !ok {
			t.Errorf("expected IP %s in persistent blocks", ip)
		}
		if blocks[ip].Geolocation.City != "Berlin" {
			t.Errorf("expected city Berlin, got %s", blocks[ip].Geolocation.City)
		}

		err = repo.DeletePersistentBlock(ip)
		if err != nil {
			t.Errorf("DeletePersistentBlock failed: %v", err)
		}
		blocks2, _ := repo.GetPersistentBlocks()
		if _, ok := blocks2[ip]; ok {
			t.Error("IP still exists after deletion")
		}
	})

	t.Run("APITokens", func(t *testing.T) {
		token := models.APIToken{
			TokenHash: "token_hash_123",
			Name:      "test-token",
			Username:  "admin_test",
			Role:      "operator",
		}

		err := repo.CreateAPIToken(token)
		if err != nil {
			t.Errorf("CreateAPIToken failed: %v", err)
		}

		got, err := repo.GetAPITokenByHash(token.TokenHash)
		if err != nil {
			t.Errorf("GetAPITokenByHash failed: %v", err)
		}
		if got.Name != "test-token" {
			t.Errorf("expected name test-token, got %s", got.Name)
		}

		err = repo.UpdateTokenLastUsed(got.ID)
		if err != nil {
			t.Errorf("UpdateTokenLastUsed failed: %v", err)
		}
	})
}
