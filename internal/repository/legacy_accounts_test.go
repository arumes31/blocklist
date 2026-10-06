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

func TestLegacyAccountCompatibility(t *testing.T) {
	ctx := t.Context()
	container, err := tcpostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("legacy_compatibility_test"),
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
	require.NoError(t, migration.Steps(16))
	repo, err := NewPostgresRepository(connection, connection, 8)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, errors.Join(repo.db.Close(), repo.readDb.Close())) })
	require.NoError(t, repo.CreateAdmin(models.AdminAccount{
		Username: "before-upgrade", PasswordHash: "preserved-hash", Token: "preserved-mfa",
		Role: "operator", Permissions: "gui_read,view_ips",
	}))
	require.NoError(t, migration.Up())
	legacy, err := repo.GetAdmin("before-upgrade")
	require.NoError(t, err)
	require.Nil(t, legacy.RoleID)
	require.Equal(t, "gui_read,view_ips", legacy.Permissions)
	for _, permission := range []string{"view_audit_logs", "view_event_logs", "manage_views"} {
		require.True(t, models.HasPermission(models.WorkspacePermissions(*legacy), permission))
	}
	// Tokens continue using the original stored owner rights, not UI aliases.
	require.Equal(t, "view_ips", models.IntersectPermissions("view_ips,manage_views", legacy.Permissions))
	require.NoError(t, repo.UpdateLegacyAdminPermissions(ctx, *legacy, "gui_read", "test-admin"))
	updated, err := repo.GetAdmin(legacy.Username)
	require.NoError(t, err)
	require.Equal(t, legacy.SessionVersion+1, updated.SessionVersion)
	require.Equal(t, legacy.PasswordHash, updated.PasswordHash)
	require.Equal(t, legacy.Token, updated.Token)
	require.Equal(t, "gui_read", models.WorkspacePermissions(*updated))
	require.ErrorIs(t, repo.UpdateLegacyAdminPermissions(ctx, *legacy, "view_ips", "test-admin"), ErrIdentityConflict)
	require.NoError(t, repo.UpdateLegacyAdminPermissions(ctx, *updated, "", "test-admin"))
	updated, err = repo.GetAdmin(legacy.Username)
	require.NoError(t, err)
	require.Empty(t, updated.Permissions, "an empty legacy update must revoke all permissions")

	created := models.AdminAccount{
		Username: "old-script", AuthSource: "local", Role: "custom-operator",
		PasswordHash: "new-hash", Permissions: "gui_read,view_ips",
	}
	require.NoError(t, repo.CreateLegacyAdmin(ctx, created, "test-admin"))
	require.ErrorIs(t, repo.CreateLegacyAdmin(ctx, created, "test-admin"), ErrIdentityConflict)
	stored, err := repo.GetAdmin(created.Username)
	require.NoError(t, err)
	require.Nil(t, stored.RoleID)
	require.Equal(t, created.Role, stored.Role)
	require.Equal(t, created.Permissions, stored.Permissions)
	require.Equal(t, 1, stored.SessionVersion)
	require.Empty(t, stored.Token, "new local account still requires authenticator enrollment")

	role := models.AccessRole{ID: "compatibility-role", Name: "Compatibility role", Permissions: "gui_read,view_ips"}
	require.NoError(t, repo.SaveRole(ctx, role, "test-admin"))
	require.NoError(t, repo.AssignAdminRole(
		ctx, models.AdminAccount{Username: stored.Username, Role: role.ID}, "test-admin",
	))
	// Assignment did not bump the session version; role_id still detects the race.
	require.ErrorIs(t, repo.UpdateLegacyAdminPermissions(ctx, *stored, "gui_read", "test-admin"), ErrIdentityConflict)
	managed, err := repo.GetAdmin(stored.Username)
	require.NoError(t, err)
	role.Revision, role.Permissions = 1, "gui_read,view_ips,manage_admins"
	require.NoError(t, repo.SaveRole(ctx, role, "test-admin"))
	// A role definition edit does not bump the account version either.
	require.ErrorIs(t, repo.UpdateLegacyAdminPermissions(ctx, *managed, "gui_read", "test-admin"), ErrIdentityConflict)
	managed, err = repo.GetAdmin(stored.Username)
	require.NoError(t, err)
	require.NoError(t, repo.CreateManagedAdmin(ctx, models.AdminAccount{
		Username: "other-member", AuthSource: "local", Role: role.ID, PasswordHash: "other-hash",
	}, "test-admin"))
	require.NoError(t, repo.UpdateLegacyAdminPermissions(ctx, *managed, "gui_read", "test-admin"))
	detached, err := repo.GetAdmin(managed.Username)
	require.NoError(t, err)
	require.Nil(t, detached.RoleID)
	require.Equal(t, "gui_read", detached.Permissions)
	require.Equal(t, managed.SessionVersion+1, detached.SessionVersion)
	other, err := repo.GetAdmin("other-member")
	require.NoError(t, err)
	require.Equal(t, role.ID, *other.RoleID)
	require.Equal(t, role.Permissions, other.Permissions, "the shared role must not change")
	logs, count, err := repo.ListLogs(ctx, models.LogFilter{Category: "system", Action: "CHANGE_PERMISSIONS", Limit: 50})
	require.NoError(t, err)
	require.Equal(t, 3, count, "only committed updates create audit entries")
	require.Len(t, logs, 3)
}
