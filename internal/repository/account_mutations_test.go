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

func TestManagedAccountMutationsUseAuthorizedSnapshots(t *testing.T) {
	ctx := t.Context()
	container, err := tcpostgres.Run(
		ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("account_mutations_test"),
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
	require.NoError(t, migration.Up())
	repo, err := NewPostgresRepository(connection, connection, 8)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, errors.Join(repo.db.Close(), repo.readDb.Close())) })

	const recovery = "recovery"
	create := func(t *testing.T, username, role string) {
		t.Helper()
		require.NoError(t, repo.CreateManagedAdmin(
			ctx, models.AdminAccount{Username: username, AuthSource: "local", Role: role, PasswordHash: "hash"}, recovery,
		))
	}
	get := func(t *testing.T, username string) models.AdminAccount {
		t.Helper()
		account, err := repo.GetAdmin(username)
		require.NoError(t, err)
		return *account
	}
	asRecovery := func(target models.AdminAccount) models.AdminMutation {
		return models.AdminMutation{Expected: target, Actor: recovery, RecoveryAdmin: recovery}
	}
	create(t, recovery, "editor")

	t.Run("password change rejects a promoted target", func(t *testing.T) {
		create(t, "pw-target", "viewer")
		snapshot := get(t, "pw-target")
		require.NoError(t, repo.AssignAdminRole(ctx, models.AdminAccount{Username: "pw-target", Role: "editor"}, recovery))
		require.ErrorIs(t, repo.ChangeManagedAdminPassword(ctx, asRecovery(snapshot), "new-hash"), ErrIdentityConflict)
		require.Equal(t, "hash", get(t, "pw-target").PasswordHash)

		fresh := get(t, "pw-target")
		require.NoError(t, repo.ChangeManagedAdminPassword(ctx, asRecovery(fresh), "new-hash"))
		changed := get(t, "pw-target")
		require.Equal(t, "new-hash", changed.PasswordHash)
		require.Equal(t, fresh.SessionVersion+1, changed.SessionVersion)
	})

	t.Run("delete and authenticator reset reject a replaced account", func(t *testing.T) {
		create(t, "replaced", "viewer")
		snapshot := get(t, "replaced")
		require.NoError(t, repo.DeleteAdmin("replaced"))
		create(t, "replaced", "editor")
		require.ErrorIs(t, repo.DeleteManagedAdmin(ctx, asRecovery(snapshot)), ErrIdentityConflict)
		require.ErrorIs(t, repo.ResetManagedAdminTOTP(ctx, asRecovery(snapshot)), ErrIdentityConflict)
		require.NoError(t, repo.DeleteManagedAdmin(ctx, asRecovery(get(t, "replaced"))))
		_, err := repo.GetAdmin("replaced")
		require.Error(t, err)
	})

	t.Run("creation and assignment bind the authorized role revision", func(t *testing.T) {
		role := models.AccessRole{ID: "growing", Name: "Growing", Permissions: "gui_read,view_ips"}
		require.NoError(t, repo.SaveRole(ctx, role, recovery))
		checked, err := repo.GetRole(ctx, "growing")
		require.NoError(t, err)
		expanded := *checked
		expanded.Permissions = "gui_read,view_ips,manage_admins"
		require.NoError(t, repo.SaveRole(ctx, expanded, recovery))

		account := models.AdminAccount{Username: "late-grant", AuthSource: "local", Role: "growing", PasswordHash: "hash"}
		require.ErrorIs(t, repo.CreateManagedAdminAtRevision(ctx, account, recovery, checked.Revision), ErrIdentityConflict)
		require.NoError(t, repo.CreateManagedAdminAtRevision(ctx, account, recovery, checked.Revision+1))

		create(t, "assign-target", "viewer")
		assignment := models.RoleAssignment{
			AdminMutation: asRecovery(get(t, "assign-target")), RoleID: "growing", RoleRevision: checked.Revision,
		}
		require.ErrorIs(t, repo.AssignManagedAdminRole(ctx, assignment), ErrIdentityConflict)
		assignment.RoleRevision = checked.Revision + 1
		require.NoError(t, repo.AssignManagedAdminRole(ctx, assignment))
		require.Equal(t, "growing", get(t, "assign-target").Role)
	})

	t.Run("delegated manager cannot clear an entra role override", func(t *testing.T) {
		delegate := models.AccessRole{ID: "delegate", Name: "Delegate", Permissions: "gui_read,view_ips,view_admins,manage_admins," +
			"view_stats,view_audit_logs,view_event_logs,view_whitelist,view_excluded,view_settings,view_roles,view_api_tokens,export_data"}
		require.NoError(t, repo.SaveRole(ctx, delegate, recovery))
		create(t, "delegated", "delegate")
		tenant, object := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
		require.NoError(t, repo.CreateManagedAdmin(ctx, models.AdminAccount{
			Username: "entra-member", AuthSource: "entra", Role: "viewer", EntraUPN: "member@example.test",
			EntraTenantID: &tenant, EntraObjectID: &object,
		}, recovery))
		require.NoError(t, repo.AssignAdminRole(ctx, models.AdminAccount{Username: "entra-member", Role: "viewer", EntraRoleOverride: true}, recovery))
		viewer, err := repo.GetRole(ctx, "viewer")
		require.NoError(t, err)

		target := get(t, "entra-member")
		assignment := models.RoleAssignment{
			AdminMutation: models.AdminMutation{Expected: target, Actor: "delegated", RecoveryAdmin: recovery},
			RoleID:        "viewer", RoleRevision: viewer.Revision, Override: false,
		}
		require.ErrorIs(t, repo.AssignManagedAdminRole(ctx, assignment), ErrIdentityDenied)
		require.True(t, get(t, "entra-member").EntraRoleOverride)

		assignment.Override = true
		require.NoError(t, repo.AssignManagedAdminRole(ctx, assignment), "keeping the override stays allowed")
	})

	t.Run("ip history only returns enforcement events", func(t *testing.T) {
		require.NoError(t, repo.LogAction(recovery, "BLOCK", "192.0.2.10", "scanner"))
		require.NoError(t, repo.LogAction("someone", "LOGIN_FAILURE", "192.0.2.10", "Invalid Password"))
		history, err := repo.GetIPHistory("192.0.2.10")
		require.NoError(t, err)
		require.Len(t, history, 1)
		require.Equal(t, "BLOCK", history[0].Action)
	})
}
