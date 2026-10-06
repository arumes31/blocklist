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

func TestAccountStatus(t *testing.T) {
	ctx := t.Context()
	container, err := tcpostgres.Run(
		ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("account_status_test"),
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
	require.NoError(t, migration.Migrate(17))
	repo, err := NewPostgresRepository(connection, connection, 8)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, errors.Join(repo.db.Close(), repo.readDb.Close())) })
	legacy := models.AdminAccount{
		Username: "legacy", PasswordHash: "preserved-hash", Token: "preserved-mfa", Role: "viewer", Permissions: "gui_read",
	}
	require.NoError(t, repo.CreateAdmin(legacy))
	require.NoError(t, migration.Up())
	upgraded, err := repo.GetAdmin(legacy.Username)
	require.NoError(t, err)
	require.False(t, upgraded.Disabled, "migration must keep every existing account enabled")
	require.Equal(t, legacy.PasswordHash, upgraded.PasswordHash)
	require.Equal(t, legacy.Token, upgraded.Token)
	require.Equal(t, legacy.Permissions, upgraded.Permissions)

	create := func(t *testing.T, username, role string) {
		t.Helper()
		require.NoError(t, repo.CreateManagedAdmin(
			ctx, models.AdminAccount{Username: username, AuthSource: "local", Role: role, PasswordHash: "preserved"}, "recovery",
		))
	}
	get := func(t *testing.T, username string) models.AdminAccount {
		t.Helper()
		account, err := repo.GetAdmin(username)
		require.NoError(t, err)
		return *account
	}
	change := func(t *testing.T, username string, disabled bool) error {
		t.Helper()
		return repo.SetAdminDisabled(ctx, models.AdminStatusChange{
			Expected: get(t, username), Disabled: disabled, Actor: "recovery", RecoveryAdmin: "recovery",
		})
	}
	create(t, "recovery", "editor")

	t.Run("legacy target permissions and recovery authority", func(t *testing.T) {
		create(t, "legacy-manager", "editor")
		for _, tc := range []struct {
			name, actor, permissions string
			allowed                  bool
		}{
			{name: "retired", actor: "legacy-manager", permissions: "gui_read,gui_write,webhook_access,view_ips", allowed: true},
			{name: "unknown", actor: "legacy-manager", permissions: "gui_read,unknown_permission"},
			{name: "recovery-unknown", actor: "recovery", permissions: "gui_read,unknown_permission", allowed: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				username := "legacy-target-" + tc.name
				require.NoError(t, repo.CreateAdmin(models.AdminAccount{
					Username: username, PasswordHash: "preserved", Permissions: tc.permissions,
				}))
				before := get(t, username)
				err := repo.SetAdminDisabled(ctx, models.AdminStatusChange{
					Expected: before, Disabled: true, Actor: tc.actor, RecoveryAdmin: "recovery",
				})
				if tc.allowed {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, ErrIdentityDenied)
				}
				after := get(t, username)
				require.Equal(t, tc.allowed, after.Disabled)
				require.Equal(t, before.Permissions, after.Permissions)
			})
		}
	})

	t.Run("disabled recovery cannot bypass authority", func(t *testing.T) {
		create(t, "disabled-recovery", "editor")
		create(t, "disabled-recovery-target", "viewer")
		require.NoError(t, change(t, "disabled-recovery", true))
		err := repo.SetAdminDisabled(ctx, models.AdminStatusChange{
			Expected: get(t, "disabled-recovery-target"), Disabled: true,
			Actor: "disabled-recovery", RecoveryAdmin: "disabled-recovery",
		})
		require.ErrorIs(t, err, ErrIdentityDenied)
		require.False(t, get(t, "disabled-recovery-target").Disabled)
	})

	t.Run("transitions preserve data revoke sessions and audit atomically", func(t *testing.T) {
		create(t, "lifecycle", "viewer")
		require.NoError(t, repo.UpdateAdminToken("lifecycle", "preserved-mfa"))
		before := get(t, "lifecycle")
		token := models.APIToken{
			Username: before.Username, Name: "preserved-token", TokenHash: "synthetic-hash", Permissions: "view_ips",
		}
		require.NoError(t, repo.CreateAPIToken(token))
		for index, disabled := range []bool{true, false} {
			require.NoError(t, change(t, before.Username, disabled))
			after := get(t, before.Username)
			require.Equal(t, disabled, after.Disabled)
			require.Equal(t, before.SessionVersion+index+1, after.SessionVersion)
			require.Equal(t, before.PasswordHash, after.PasswordHash)
			require.Equal(t, before.Token, after.Token)
			require.Equal(t, before.RoleID, after.RoleID)
			stored, err := repo.GetAPITokenByHash(token.TokenHash)
			require.NoError(t, err)
			require.Equal(t, token.Username, stored.Username)
			require.Equal(t, token.Permissions, stored.Permissions)
			// Repeating the same desired state is a no-op, not another invalidation.
			require.NoError(t, change(t, before.Username, disabled))
			require.Equal(t, after.SessionVersion, get(t, before.Username).SessionVersion)
			if disabled {
				require.ErrorIs(t, repo.UpdateAdminToken(before.Username, "replacement"), ErrIdentityDenied)
			}
		}
		var actions []string
		require.NoError(t, repo.db.SelectContext(ctx, &actions,
			"SELECT action FROM audit_logs WHERE target = $1 AND action IN ('DISABLE_ADMIN', 'ENABLE_ADMIN') ORDER BY id",
			before.Username))
		require.Equal(t, []string{"DISABLE_ADMIN", "ENABLE_ADMIN"}, actions)
	})

	t.Run("recovery self and insufficient authority are protected", func(t *testing.T) {
		create(t, "limited", "viewer")
		create(t, "protected-target", "editor")
		for _, names := range [][2]string{{"recovery", "recovery"}, {"limited", "limited"}, {"limited", "protected-target"}} {
			err := repo.SetAdminDisabled(ctx, models.AdminStatusChange{
				Expected: get(t, names[1]), Disabled: true, Actor: names[0], RecoveryAdmin: "recovery",
			})
			require.ErrorIs(t, err, ErrIdentityDenied)
			require.False(t, get(t, names[1]).Disabled)
		}
	})

	t.Run("stale role and session snapshots cannot change status", func(t *testing.T) {
		create(t, "stale", "viewer")
		before := get(t, "stale")
		require.NoError(t, repo.AssignAdminRole(ctx, models.AdminAccount{Username: "stale", Role: "moderator"}, "recovery"))
		err := repo.SetAdminDisabled(ctx, models.AdminStatusChange{
			Expected: before, Disabled: true, Actor: "recovery", RecoveryAdmin: "recovery",
		})
		require.ErrorIs(t, err, ErrIdentityConflict)
		before = get(t, "stale")
		require.NoError(t, repo.UpdateAdminToken("stale", "changed-mfa"))
		err = repo.SetAdminDisabled(ctx, models.AdminStatusChange{
			Expected: before, Disabled: true, Actor: "recovery", RecoveryAdmin: "recovery",
		})
		require.ErrorIs(t, err, ErrIdentityConflict)
		require.False(t, get(t, "stale").Disabled)
	})

	t.Run("concurrent managers cannot disable each other", func(t *testing.T) {
		create(t, "manager-a", "editor")
		create(t, "manager-b", "editor")
		a, b := get(t, "manager-a"), get(t, "manager-b")
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, request := range []models.AdminStatusChange{
			{Expected: a, Disabled: true, Actor: b.Username, RecoveryAdmin: "recovery"},
			{Expected: b, Disabled: true, Actor: a.Username, RecoveryAdmin: "recovery"},
		} {
			go func() {
				<-start
				results <- repo.SetAdminDisabled(ctx, request)
			}()
		}
		close(start)
		var successes int
		for range 2 {
			if err := <-results; err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, ErrIdentityDenied)
			}
		}
		require.Equal(t, 1, successes)
		require.NotEqual(t, get(t, a.Username).Disabled, get(t, b.Username).Disabled)
	})

	t.Run("role permission edits invalidate the authorized snapshot", func(t *testing.T) {
		role := models.AccessRole{ID: "status-reviewer", Name: "Status reviewer", Permissions: "gui_read,view_admins"}
		require.NoError(t, repo.SaveRole(ctx, role, "recovery"))
		create(t, "role-edit-target", role.ID)
		before := get(t, "role-edit-target")
		stored, err := repo.GetRole(ctx, role.ID)
		require.NoError(t, err)
		stored.Permissions += ",manage_admins"
		require.NoError(t, repo.SaveRole(ctx, *stored, "recovery"))
		require.Equal(t, before.SessionVersion, get(t, before.Username).SessionVersion)
		err = repo.SetAdminDisabled(ctx, models.AdminStatusChange{
			Expected: before, Disabled: true, Actor: "recovery", RecoveryAdmin: "recovery",
		})
		require.ErrorIs(t, err, ErrIdentityConflict)
		require.False(t, get(t, before.Username).Disabled)
	})

	t.Run("disabled Entra invitations and bound identities cannot reprovision", func(t *testing.T) {
		identity := models.EntraIdentity{
			TenantID: "11111111-1111-1111-1111-111111111111", ObjectID: "22222222-2222-2222-2222-222222222222",
			UPN: "disabled@example.test", RoleID: "viewer",
		}
		require.NoError(t, repo.CreateManagedAdmin(ctx, models.AdminAccount{
			Username: identity.UPN, EntraUPN: identity.UPN, AuthSource: "entra", Role: "viewer",
		}, "recovery"))
		for _, bound := range []bool{false, true} {
			require.NoError(t, change(t, identity.UPN, true))
			for _, autoProvision := range []bool{false, true} {
				_, err := repo.SignInEntra(ctx, identity, autoProvision)
				require.ErrorIs(t, err, ErrIdentityDenied)
			}
			account := get(t, identity.UPN)
			require.Equal(t, bound, account.EntraObjectID != nil)
			require.NoError(t, change(t, identity.UPN, false))
			accountAfter, err := repo.SignInEntra(ctx, identity, true)
			require.NoError(t, err)
			require.Equal(t, identity.UPN, accountAfter.Username)
			require.Equal(t, identity.ObjectID, *accountAfter.EntraObjectID)
		}
	})
}
