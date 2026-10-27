//go:build integration

package repository

import (
	"errors"
	"testing"

	"blocklist/internal/models"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestAccountLabels(t *testing.T) {
	ctx := t.Context()
	container, err := tcpostgres.Run(
		ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("account_labels_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("synthetic-test-password"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)
	connection, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	migration, err := migrate.New("file://../../cmd/server/migrations", connection)
	require.NoError(t, err)
	t.Cleanup(func() {
		sourceErr, databaseErr := migration.Close()
		require.NoError(t, errors.Join(sourceErr, databaseErr))
	})
	require.NoError(t, migration.Migrate(18))
	repo, err := NewPostgresRepository(connection, connection, 8)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, errors.Join(repo.db.Close(), repo.readDb.Close())) })

	const (
		tenant      = "11111111-1111-1111-1111-111111111111"
		existingKey = "entra:" + tenant + ":22222222-2222-2222-2222-000000000001"
		newKey      = "entra:" + tenant + ":22222222-2222-2222-2222-000000000002"
	)
	_, err = repo.db.ExecContext(ctx, `INSERT INTO admins
		(username, password_hash, token, role, permissions, auth_source, entra_tenant_id, entra_object_id, entra_upn, role_id)
		VALUES ($1, '', '', 'editor', 'gui_read', 'entra', $2, $3, ' existing@example.test ', 'editor'),
		('invited@example.test', '', '', 'viewer', 'gui_read', 'entra', NULL, NULL, 'invited@example.test', 'viewer')`,
		existingKey, tenant, "22222222-2222-2222-2222-000000000001",
	)
	require.NoError(t, err)
	require.NoError(t, migration.Up())

	labels, err := repo.AccountLabels(ctx)
	require.NoError(t, err)
	require.Equal(t, map[string]string{existingKey: "existing@example.test"}, labels,
		"the upgrade labels existing account keys only; invitations already use the sign-in name")

	identity := models.EntraIdentity{
		TenantID: tenant, ObjectID: "22222222-2222-2222-2222-000000000002", UPN: "New.Person@example.test", RoleID: "moderator",
	}
	account, err := repo.SignInEntra(ctx, identity, true)
	require.NoError(t, err)
	require.Equal(t, newKey, account.Username)
	identity.UPN = "renamed@example.test"
	_, err = repo.SignInEntra(ctx, identity, true)
	require.NoError(t, err)
	identity.UPN = ""
	_, err = repo.SignInEntra(ctx, identity, true)
	require.NoError(t, err)
	labels, err = repo.AccountLabels(ctx)
	require.NoError(t, err)
	require.Equal(t, "renamed@example.test", labels[newKey], "a missing UPN keeps the last known name")

	require.NoError(t, repo.LogAction("admin", "ASSIGN_ROLE", newKey, "Role: editor"))
	require.NoError(t, repo.DeleteAdmin(newKey))
	labels, err = repo.AccountLabels(ctx)
	require.NoError(t, err)
	require.Equal(t, "renamed@example.test", labels[newKey], "deleted accounts keep their name in history")

	logs, total, err := repo.ListLogs(ctx, models.LogFilter{Category: "system", Actor: "RENAMED@example.test", Limit: 50})
	require.NoError(t, err)
	require.Equal(t, 3, total, "the actor filter accepts the sign-in name")
	for _, entry := range logs {
		require.Equal(t, newKey, entry.Actor)
	}
	_, total, err = repo.ListLogs(ctx, models.LogFilter{Category: "system", Actor: newKey, Limit: 50})
	require.NoError(t, err)
	require.Equal(t, 3, total, "the actor filter still accepts the stored key")
	logs, total, err = repo.ListLogs(ctx, models.LogFilter{Category: "system", Query: "renamed@", Limit: 50})
	require.NoError(t, err)
	require.Equal(t, 1, total, "search finds targets by sign-in name")
	require.Equal(t, "ASSIGN_ROLE", logs[0].Action)

	require.NoError(t, migration.Steps(-1))
	var exists bool
	require.NoError(t, repo.db.GetContext(ctx, &exists, "SELECT to_regclass('account_labels') IS NOT NULL"))
	require.False(t, exists)
}
