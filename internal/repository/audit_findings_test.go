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

func auditFindingsRepository(t *testing.T) *PostgresRepository {
	t.Helper()
	if testing.Short() {
		t.Skip("requires a disposable PostgreSQL container")
	}
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine", tcpostgres.WithDatabase("audit_test"), tcpostgres.WithUsername("postgres"), tcpostgres.WithPassword("synthetic-test-password"), tcpostgres.BasicWaitStrategies())
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)
	connection, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	migration, err := migrate.New("file://../../cmd/server/migrations", connection)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = migration.Close() })
	require.NoError(t, migration.Up())
	repo, err := NewPostgresRepository(connection, connection, 2)
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.db.Close(); _ = repo.readDb.Close() })
	return repo
}

// A deleted and recreated username must start above every session version the
// old account issued, or its unexpired sessions would pass SessionCheckMiddleware.
func TestRecreatedAccountStartsAboveDeletedSessionVersion(t *testing.T) {
	repo := auditFindingsRepository(t)
	ctx := context.Background()

	fresh := models.AdminAccount{Username: "bob", AuthSource: "local", Role: "viewer", PasswordHash: "synthetic-hash"}
	require.NoError(t, repo.CreateManagedAdmin(ctx, fresh, "test"))
	created, err := repo.GetAdmin("bob")
	require.NoError(t, err)
	require.Equal(t, 1, created.SessionVersion, "brand-new usernames still start at 1")

	require.NoError(t, repo.IncrementSessionVersion("bob"))
	require.NoError(t, repo.IncrementSessionVersion("bob"))
	before, err := repo.GetAdmin("bob")
	require.NoError(t, err)

	require.NoError(t, repo.DeleteAdmin("bob"))
	require.NoError(t, repo.CreateManagedAdmin(ctx, fresh, "test"))
	recreated, err := repo.GetAdmin("bob")
	require.NoError(t, err)
	require.Greater(t, recreated.SessionVersion, before.SessionVersion)

	require.NoError(t, repo.DeleteAdmin("bob"))
	require.NoError(t, repo.CreateLegacyAdmin(ctx, models.AdminAccount{Username: "bob", AuthSource: "local", PasswordHash: "synthetic-hash", Role: "operator", Permissions: "gui_read"}, "test"))
	legacy, err := repo.GetAdmin("bob")
	require.NoError(t, err)
	require.Greater(t, legacy.SessionVersion, recreated.SessionVersion, "every creation path honours the floor")
}

// Guest/external identities carry a preferred_username this tenant does not
// control, so they must never claim a UPN-only invitation.
func TestExternalIdentityCannotClaimUPNInvitation(t *testing.T) {
	repo := auditFindingsRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.CreateManagedAdmin(ctx, models.AdminAccount{
		Username: "invitee@example.test", AuthSource: "entra", Role: "viewer", EntraUPN: "invitee@example.test",
	}, "test"))

	guest := models.EntraIdentity{
		TenantID: "11111111-1111-1111-1111-111111111111", ObjectID: "22222222-2222-2222-2222-222222222222",
		UPN: "invitee@example.test", RoleID: "viewer", External: true,
	}
	_, err := repo.SignInEntra(ctx, guest, false)
	require.ErrorIs(t, err, ErrIdentityDenied)

	member := guest
	member.ObjectID = "33333333-3333-3333-3333-333333333333"
	member.External = false
	account, err := repo.SignInEntra(ctx, member, false)
	require.NoError(t, err)
	require.Equal(t, "invitee@example.test", account.Username)
}
