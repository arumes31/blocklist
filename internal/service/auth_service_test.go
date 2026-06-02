package service

import (
	"context"
	"testing"
	"time"

	"blocklist/internal/repository"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestAuthService_HashPassword(t *testing.T) {
	svc := NewAuthService(nil, nil)
	pass := "secret123"
	hash, err := svc.HashPassword(pass)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == pass {
		t.Error("hash should not be equal to password")
	}
}

func TestAuthService_Integration(t *testing.T) {
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
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}
	defer func() {
		_ = pgContainer.Terminate(ctx)
	}()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %s", err)
	}

	// Run migrations
	m, err := migrate.New("file://../../cmd/server/migrations", connStr)
	if err != nil {
		t.Fatalf("failed to init migrate: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to run migrations: %v", err)
	}

	pgRepo, err := repository.NewPostgresRepository(connStr, connStr, 0)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}

	svc := NewAuthService(pgRepo, nil)

	t.Run("CreateAdmin and CheckAuth", func(t *testing.T) {
		admin, err := svc.CreateAdmin("admin_test", "supersecret", "admin", "all")
		assert.NoError(t, err)
		assert.NotNil(t, admin)
		assert.Equal(t, "admin_test", admin.Username)

		// Create TOTP secret for the user
		secret, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Blocklist",
			AccountName: "admin_test",
		})
		assert.NoError(t, err)

		// Update TOTP secret in DB
		err = pgRepo.UpdateAdminToken("admin_test", secret.Secret())
		assert.NoError(t, err)

		// Check Auth
		passCode, err := totp.GenerateCode(secret.Secret(), time.Now())
		assert.NoError(t, err)

		authed := svc.CheckAuth("admin_test", "supersecret", passCode)
		assert.True(t, authed)

		// Wrong password
		assert.False(t, svc.CheckAuth("admin_test", "wrongpass", passCode))

		// Wrong totp code
		assert.False(t, svc.CheckAuth("admin_test", "supersecret", "000000"))

		// VerifyTOTP directly
		assert.True(t, svc.VerifyTOTP("admin_test", passCode))
		assert.False(t, svc.VerifyTOTP("admin_test", "111111"))

		// Non-existent user
		assert.False(t, svc.CheckAuth("ghost", "supersecret", passCode))
		assert.False(t, svc.VerifyTOTP("ghost", passCode))
	})
}
