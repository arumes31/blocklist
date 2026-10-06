//go:build integration

package repository

import (
	"context"
	"testing"

	"blocklist/internal/models"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestIdentityRepository(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a disposable PostgreSQL container")
	}
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine", tcpostgres.WithDatabase("identity_test"), tcpostgres.WithUsername("postgres"), tcpostgres.WithPassword("synthetic-test-password"), tcpostgres.BasicWaitStrategies())
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)
	connection, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	migration, err := migrate.New("file://../../cmd/server/migrations", connection)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = migration.Close() })
	require.NoError(t, migration.Steps(16))
	repo, err := NewPostgresRepository(connection, connection, 2)
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.db.Close(); _ = repo.readDb.Close() })
	require.NoError(t, repo.CreateAdmin(models.AdminAccount{Username: "legacy", PasswordHash: "unchanged-hash", Token: "unchanged-secret", Role: "operator", Permissions: "gui_read,view_ips"}))
	require.NoError(t, migration.Up())
	legacy, err := repo.GetAdmin("legacy")
	require.NoError(t, err)
	require.Nil(t, legacy.RoleID)
	require.Equal(t, "gui_read,view_ips", legacy.Permissions)
	require.Equal(t, "unchanged-hash", legacy.PasswordHash)
	require.Equal(t, "unchanged-secret", legacy.Token)
	roles, err := repo.ListRoles(ctx)
	require.NoError(t, err)
	require.Len(t, roles, 3)
	viewer, err := repo.GetRole(ctx, "viewer")
	require.NoError(t, err)
	moderator, err := repo.GetRole(ctx, "moderator")
	require.NoError(t, err)
	editor, err := repo.GetRole(ctx, "editor")
	require.NoError(t, err)
	for _, permission := range models.PermissionCatalog {
		require.Equal(t, permission.Group == "Read", models.HasPermission(viewer.Permissions, permission.Key), permission.Key)
		allowed := permission.Group == "Read" || permission.Key == "whitelist_ips" || permission.Key == "exclude_ips" || permission.Key == "unblock_ips"
		require.Equal(t, allowed, models.HasPermission(moderator.Permissions, permission.Key), permission.Key)
		require.True(t, models.HasPermission(editor.Permissions, permission.Key), permission.Key)
	}
	role := models.AccessRole{ID: "incident-review", Name: "Incident review", Permissions: "gui_read,view_ips"}
	require.NoError(t, repo.SaveRole(ctx, role, "legacy"))
	require.NoError(t, repo.AssignAdminRole(ctx, models.AdminAccount{Username: "legacy", Role: role.ID}, "legacy"))
	require.ErrorIs(t, repo.DeleteRole(
		ctx,
		role.ID,
		"legacy",
		1,
	), ErrRoleInUse)
	require.ErrorIs(t, repo.DeleteRole(
		ctx,
		"viewer",
		"legacy",
		1,
	), ErrRoleProtected)
	role.Revision = 1
	role.Permissions = "gui_read"
	require.NoError(t, repo.SaveRole(ctx, role, "legacy"))
	require.ErrorIs(t, repo.SaveRole(ctx, role, "legacy"), ErrIdentityConflict)
	legacy, err = repo.GetAdmin("legacy")
	require.NoError(t, err)
	require.Equal(t, "gui_read", legacy.Permissions, "role changes apply without waiting for session refresh")
	require.NoError(t, repo.AssignAdminRole(ctx, models.AdminAccount{Username: "legacy", Role: "viewer"}, "legacy"))
	for _, revision := range []int{0, 1, 3} {
		require.ErrorIs(t, repo.DeleteRole(
			ctx,
			role.ID,
			"legacy",
			revision,
		), ErrIdentityConflict)
		_, err := repo.GetRole(ctx, role.ID)
		require.NoError(t, err, "rejected deletion must preserve the role")
	}
	require.NoError(t, repo.DeleteRole(
		ctx,
		role.ID,
		"legacy",
		2,
	))

	tenant, object := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	require.NoError(t, repo.CreateManagedAdmin(ctx, models.AdminAccount{Username: "entra-person", AuthSource: "entra", Role: "viewer", EntraUPN: "reused@example.test", EntraTenantID: &tenant, EntraObjectID: &object}, "legacy"))
	identity := models.EntraIdentity{TenantID: tenant, ObjectID: "33333333-3333-3333-3333-333333333333", UPN: "reused@example.test", RoleID: "editor"}
	_, err = repo.SignInEntra(ctx, identity, false)
	require.ErrorIs(t, err, ErrIdentityDenied, "reused UPN must never claim another identity")
	identity.ObjectID = object
	account, err := repo.SignInEntra(ctx, identity, false)
	require.NoError(t, err)
	require.Equal(t, "entra-person", account.Username)
	require.Equal(t, "editor", account.Role)
	require.NoError(t, repo.AssignAdminRole(ctx, models.AdminAccount{Username: account.Username, Role: "viewer", EntraRoleOverride: true}, "legacy"))
	account, err = repo.SignInEntra(ctx, identity, false)
	require.NoError(t, err)
	require.Equal(t, "viewer", account.Role)
	identity.ObjectID = "44444444-4444-4444-4444-444444444444"
	account, err = repo.SignInEntra(ctx, identity, true)
	require.NoError(t, err)
	require.Equal(t, "entra:"+tenant+":"+identity.ObjectID, account.Username)

	const target = "192.0.2.7"
	require.NoError(t, repo.LogAction("legacy", "SYSTEM_TARGET_TEST", target, "preserve this audit record"))
	for range 5 {
		require.NoError(t, repo.LogAction("legacy", "BLOCK", target, "event-test"))
	}
	require.NoError(t, repo.BulkLogAction("legacy", "UNBLOCK", []string{target}, "event-test"))
	logs, total, err := repo.ListLogs(ctx, models.LogFilter{Category: "system", Query: "preserve this", Limit: 50})
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Len(t, logs, 1)
	logs, total, err = repo.ListLogs(ctx, models.LogFilter{Category: "events", Actor: "legacy", Query: target, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, logs, 1)
	require.Equal(t, "UNBLOCK", logs[0].Action)
	logs, _, err = repo.ListLogs(ctx, models.LogFilter{Category: "events", Query: target, Limit: 1, Offset: 1})
	require.NoError(t, err)
	require.Equal(t, "BLOCK", logs[0].Action)
	_, _, err = repo.ListLogs(ctx, models.LogFilter{Category: "unknown", Limit: 50})
	require.Error(t, err)
}
