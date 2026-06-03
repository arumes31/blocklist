package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type MockPostgresRepo struct {
	mock.Mock
}

func (m *MockPostgresRepo) GetAdmin(username string) (*models.AdminAccount, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AdminAccount), args.Error(1)
}

func (m *MockPostgresRepo) CreateAdmin(admin models.AdminAccount) error {
	args := m.Called(admin)
	return args.Error(0)
}

func (m *MockPostgresRepo) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	args := m.Called(hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIToken), args.Error(1)
}

type MockRedisRepo struct {
	mock.Mock
}

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

func TestCheckAuthDummyForMockImports(t *testing.T) {
	// Simple test to ensure mock is imported and used
	_ = new(MockRedisRepo)
}

func TestAuthService_CheckAuth(t *testing.T) {
	t.Run("API Token - Success", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)
		token := "bl_test_token"
		hash := sha256.Sum256([]byte(token))
		hashStr := hex.EncodeToString(hash[:])
		pg.On("GetAPITokenByHash", hashStr).Return(&models.APIToken{Name: "test"}, nil).Once()

		if !svc.CheckAuth("", "", token) {
			t.Error("expected token auth to succeed")
		}
		pg.AssertExpectations(t)
	})

	t.Run("API Token - Expired", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)
		token := "bl_expired_token"
		hash := sha256.Sum256([]byte(token))
		hashStr := hex.EncodeToString(hash[:])
		expired := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		pg.On("GetAPITokenByHash", hashStr).Return(&models.APIToken{Name: "expired", ExpiresAt: &expired}, nil).Once()

		if svc.CheckAuth("", "", token) {
			t.Error("expected expired token auth to fail")
		}
		pg.AssertExpectations(t)
	})

	t.Run("API Token - Invalid", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)
		token := "bl_invalid_token"
		hash := sha256.Sum256([]byte(token))
		hashStr := hex.EncodeToString(hash[:])
		pg.On("GetAPITokenByHash", hashStr).Return(nil, errors.New("not found")).Once()

		if svc.CheckAuth("", "", token) {
			t.Error("expected invalid token auth to fail")
		}
		pg.AssertExpectations(t)
	})

	t.Run("User Auth - Success", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)
		username := "admin"
		password := "password123"
		totpSecret := "JBSWY3DPEHPK3PXP"
		passHash, _ := svc.HashPassword(password)

		code, _ := totp.GenerateCode(totpSecret, time.Now())
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])

		pg.On("GetAPITokenByHash", hashStr).Return(nil, nil).Once()
		pg.On("GetAdmin", username).Return(&models.AdminAccount{
			Username:     username,
			PasswordHash: passHash,
			Token:        totpSecret,
		}, nil).Once()

		if !svc.CheckAuth(username, password, code) {
			t.Error("expected user auth to succeed")
		}
		pg.AssertExpectations(t)
	})

	t.Run("User Auth - Wrong Password", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)
		username := "admin"
		pg.On("GetAPITokenByHash", mock.Anything).Return(nil, nil).Maybe()
		pg.On("GetAdmin", username).Return(&models.AdminAccount{
			Username:     username,
			PasswordHash: "wrong_hash",
		}, nil).Once()

		if svc.CheckAuth(username, "wrong_pass", "") {
			t.Error("expected auth to fail for wrong password")
		}
		pg.AssertExpectations(t)
	})

	t.Run("User Auth - No TOTP Enrolled", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)
		username := "admin"
		password := "password123"
		passHash, _ := svc.HashPassword(password)

		code := "123456"
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])

		pg.On("GetAPITokenByHash", hashStr).Return(nil, nil).Once()
		pg.On("GetAdmin", username).Return(&models.AdminAccount{
			Username:     username,
			PasswordHash: passHash,
			Token:        "",
		}, nil).Once()

		if svc.CheckAuth(username, password, code) {
			t.Error("expected auth to fail when TOTP not enrolled")
		}
		pg.AssertExpectations(t)
	})

	t.Run("User Auth - Non-existent User", func(t *testing.T) {
		pg := new(MockPostgresRepo)
		svc := NewAuthService(pg, nil)

		code := "123456"
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])

		pg.On("GetAPITokenByHash", hashStr).Return(nil, nil).Once()
		pg.On("GetAdmin", "missing").Return(nil, errors.New("not found")).Once()
		if svc.CheckAuth("missing", "pass", code) {
			t.Error("expected auth to fail for non-existent user")
		}
		pg.AssertExpectations(t)
	})
}

func TestAuthService_VerifyTOTP(t *testing.T) {
	pg := new(MockPostgresRepo)
	svc := NewAuthService(pg, nil)

	t.Run("Success", func(t *testing.T) {
		username := "admin"
		totpSecret := "JBSWY3DPEHPK3PXP"
		pg.On("GetAdmin", username).Return(&models.AdminAccount{
			Username: username,
			Token:    totpSecret,
		}, nil).Once()

		code, _ := totp.GenerateCode(totpSecret, time.Now())
		if !svc.VerifyTOTP(username, code) {
			t.Error("expected TOTP verification to succeed")
		}
	})

	t.Run("Bypass Protection", func(t *testing.T) {
		username := "admin"
		pg.On("GetAdmin", username).Return(&models.AdminAccount{
			Username: username,
			Token:    "",
		}, nil).Once()

		if svc.VerifyTOTP(username, "000000") {
			t.Error("expected TOTP verification to fail for empty secret")
		}
	})

	pg.AssertExpectations(t)
}

func TestAuthService_CreateAdmin(t *testing.T) {
	pg := new(MockPostgresRepo)
	svc := NewAuthService(pg, nil)

	t.Run("Success", func(t *testing.T) {
		username := "newadmin"
		password := "password123"
		pg.On("CreateAdmin", mock.MatchedBy(func(admin models.AdminAccount) bool {
			return admin.Username == username && admin.Role == "admin"
		})).Return(nil).Once()

		admin, err := svc.CreateAdmin(username, password, "admin", "full")
		if err != nil {
			t.Fatalf("CreateAdmin failed: %v", err)
		}
		if admin.Username != username {
			t.Errorf("expected username %s, got %s", username, admin.Username)
		}
	})

	t.Run("Default Values", func(t *testing.T) {
		username := "operator"
		pg.On("CreateAdmin", mock.MatchedBy(func(admin models.AdminAccount) bool {
			return admin.Username == username && admin.Role == "operator" && admin.Permissions == "gui_read"
		})).Return(nil).Once()

		_, err := svc.CreateAdmin(username, "pass", "", "")
		if err != nil {
			t.Fatalf("CreateAdmin failed: %v", err)
		}
	})

	pg.AssertExpectations(t)
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
