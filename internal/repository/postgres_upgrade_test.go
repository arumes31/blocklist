//go:build integration

package repository_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/service"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestSchema16Upgrade seeds the old schema before applying current migrations.
// Until migration 17 exists, Up returns ErrNoChange; this still exercises the
// current repository and authentication service against persisted schema-16 data.
func TestSchema16Upgrade(t *testing.T) {
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("upgrade"), tcpostgres.WithUsername("ci"),
		tcpostgres.WithPassword("disposable-ci"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(time.Minute)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(ctx)) })
	url, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	migrations, err := migrate.New("file://../../cmd/server/migrations", url)
	require.NoError(t, err)
	t.Cleanup(func() {
		sourceErr, databaseErr := migrations.Close()
		require.NoError(t, sourceErr)
		require.NoError(t, databaseErr)
	})
	require.NoError(t, migrations.Migrate(16))
	db, err := sql.Open("pgx", url)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err = db.Exec(`INSERT INTO admins (username, password_hash, token, role, permissions)
		VALUES ('legacy-admin', 'synthetic-fixture', '', 'admin', 'view_ips')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO persistent_blocks (ip, reason, added_by, geo_json)
		VALUES ('192.0.2.1', 'schema-16 fixture', 'legacy-admin', '{}')`)
	require.NoError(t, err)
	for _, token := range []struct {
		name   string
		expiry any
	}{
		{"unlimited", nil},
		{"valid", time.Now().UTC().Add(time.Hour)},
		{"expired", time.Now().UTC().Add(-time.Hour)},
	} {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte("bl_fixture_"+token.name)))
		_, err = db.Exec(`INSERT INTO api_tokens
			(token_hash, name, username, role, permissions, allowed_ips, expires_at)
			VALUES ($1, $2, 'legacy-admin', 'viewer', 'view_ips', '192.0.2.0/24', $3)`,
			hash, token.name, token.expiry)
		require.NoError(t, err)
	}
	err = migrations.Up()
	if err != migrate.ErrNoChange {
		require.NoError(t, err)
	}
	_, dirty, err := migrations.Version()
	require.NoError(t, err)
	require.False(t, dirty)
	repo, err := repository.NewPostgresRepository(url, url, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	blocks, err := repo.GetPersistentBlocks()
	require.NoError(t, err)
	require.Equal(t, "schema-16 fixture", blocks["192.0.2.1"].Reason)
	auth := service.NewAuthService(repo, nil)
	for _, name := range []string{"unlimited", "valid", "expired"} {
		t.Run(name, func(t *testing.T) {
			raw := "bl_fixture_" + name
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
			token, err := repo.GetAPITokenByHash(hash)
			require.NoError(t, err)
			require.Equal(t, "view_ips", token.Permissions)
			require.Equal(t, "192.0.2.0/24", token.AllowedIPs)
			require.Equal(t, name != "expired", auth.CheckAuth("", "", raw))
			require.NoError(t, repo.UpdateTokenLastUsed(token.ID, "192.0.2.9"))
			updated, err := repo.GetAPITokenByHash(hash)
			require.NoError(t, err)
			require.Equal(t, "192.0.2.9", updated.LastUsedIP)
			require.NotNil(t, updated.LastUsed)
		})
	}
	newRaw := "bl_fixture_created_after_upgrade"
	newHash := fmt.Sprintf("%x", sha256.Sum256([]byte(newRaw)))
	require.NoError(t, repo.CreateAPIToken(models.APIToken{
		TokenHash: newHash, Name: "new", Username: "legacy-admin", Role: "viewer", Permissions: "view_ips",
	}))
	require.True(t, auth.CheckAuth("", "", newRaw))
	newToken, err := repo.GetAPITokenByHash(newHash)
	require.NoError(t, err)
	require.NoError(t, repo.DeleteAPIToken(newToken.ID, "legacy-admin"))
	require.False(t, auth.CheckAuth("", "", newRaw))
}
