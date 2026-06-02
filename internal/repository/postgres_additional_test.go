package repository

import (
	"context"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgresRepository_AdditionalCoverage(t *testing.T) {
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

	repo, err := NewPostgresRepository(connStr, connStr, 5)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer func() {
		_ = repo.Close()
	}()

	// Create a test admin for foreign keys if any
	admin := models.AdminAccount{
		Username:     "test_user",
		PasswordHash: "hash",
		Token:        "token",
		Role:         "admin",
	}
	err = repo.CreateAdmin(admin)
	assert.NoError(t, err)

	t.Run("Update and Session Management for Admin", func(t *testing.T) {
		err := repo.UpdateAdminPassword("test_user", "new_hash")
		assert.NoError(t, err)

		err = repo.UpdateAdminToken("test_user", "new_token")
		assert.NoError(t, err)

		err = repo.UpdateAdminPermissions("test_user", "write")
		assert.NoError(t, err)

		err = repo.IncrementSessionVersion("test_user")
		assert.NoError(t, err)

		adm, err := repo.GetAdmin("test_user")
		assert.NoError(t, err)
		assert.Equal(t, "new_hash", adm.PasswordHash)
		assert.Equal(t, "new_token", adm.Token)
		assert.Equal(t, "write", adm.Permissions)

		err = repo.DeleteAdmin("test_user")
		assert.NoError(t, err)

		_, err = repo.GetAdmin("test_user")
		assert.Error(t, err)
	})

	t.Run("APITokens CRUD", func(t *testing.T) {
		// Create admin first because of username foreign key
		_ = repo.CreateAdmin(admin)

		tok := models.APIToken{
			TokenHash: "hash1",
			Name:      "tok1",
			Username:  "test_user",
			Role:      "operator",
		}
		err := repo.CreateAPIToken(tok)
		assert.NoError(t, err)

		toks, err := repo.GetAPITokens("test_user")
		assert.NoError(t, err)
		assert.Len(t, toks, 1)

		allToks, err := repo.GetAllAPITokens()
		assert.NoError(t, err)
		assert.Len(t, allToks, 1)

		err = repo.UpdateAPITokenPermissions(allToks[0].ID, "test_user", "read")
		assert.NoError(t, err)

		err = repo.DeleteAPIToken(allToks[0].ID, "test_user")
		assert.NoError(t, err)

		tok2 := models.APIToken{
			TokenHash: "hash2",
			Name:      "tok2",
			Username:  "test_user",
			Role:      "operator",
		}
		_ = repo.CreateAPIToken(tok2)
		allToks2, _ := repo.GetAllAPITokens()

		err = repo.DeleteAPITokenByID(allToks2[0].ID)
		assert.NoError(t, err)
	})

	t.Run("SavedViews CRUD", func(t *testing.T) {
		view := models.SavedView{
			Username: "test_user",
			Name:     "view1",
			Filters:  "filter1",
		}
		err := repo.CreateSavedView(view)
		assert.NoError(t, err)

		views, err := repo.GetSavedViews("test_user")
		assert.NoError(t, err)
		assert.Len(t, views, 1)
		assert.Equal(t, "view1", views[0].Name)

		err = repo.DeleteSavedView(views[0].ID, "test_user")
		assert.NoError(t, err)

		views2, _ := repo.GetSavedViews("test_user")
		assert.Empty(t, views2)
	})

	t.Run("OutboundWebhooks", func(t *testing.T) {
		wh := models.OutboundWebhook{
			URL:    "http://example.com/webhook",
			Events: "ban",
			Active: true,
		}
		err := repo.CreateOutboundWebhook(wh)
		assert.NoError(t, err)

		active, err := repo.GetActiveWebhooks()
		assert.NoError(t, err)
		assert.Len(t, active, 1)

		log := models.WebhookLog{
			WebhookID:  active[0].ID,
			Event:      "ban",
			Payload:    "{}",
			StatusCode: 200,
			Attempt:    1,
		}
		err = repo.LogWebhookDelivery(log)
		assert.NoError(t, err)

		err = repo.DeleteOutboundWebhook(active[0].ID)
		assert.NoError(t, err)
	})

	t.Run("PersistentCount & AuditLogs", func(t *testing.T) {
		count, err := repo.GetPersistentCount()
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count)

		_ = repo.LogAction("test_user", "BLOCK", "1.1.1.1", "spam")
		logs, err := repo.GetAuditLogs(10)
		assert.NoError(t, err)
		assert.Len(t, logs, 1)

		logsPaginated, total, err := repo.GetAuditLogsPaginated(10, 0, "test_user", "BLOCK", "1.1.1.1")
		assert.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, logsPaginated, 1)

		trend, err := repo.GetBlockTrend()
		assert.NoError(t, err)
		assert.NotNil(t, trend)
	})
}
