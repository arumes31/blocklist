//go:build integration

package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"blocklist/internal/models"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestEntraUPNProvisioning(t *testing.T) {
	ctx := t.Context()
	container, err := tcpostgres.Run(
		ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("identity_upn_test"),
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
	const tenant = "11111111-1111-1111-1111-111111111111"
	identity := func(upn string, object int) models.EntraIdentity {
		return models.EntraIdentity{
			TenantID: tenant, ObjectID: fmt.Sprintf("22222222-2222-2222-2222-%012d", object),
			UPN: upn, RoleID: "viewer",
		}
	}
	create := func(t *testing.T, upn string) {
		t.Helper()
		require.NoError(t, repo.CreateManagedAdmin(
			ctx, models.AdminAccount{Username: upn, AuthSource: "entra", Role: "viewer", EntraUPN: upn}, "test-admin",
		))
	}
	t.Run("binds once and survives rename without upn takeover", func(t *testing.T) {
		create(t, "person@example.test")
		first := identity("PERSON@EXAMPLE.TEST", 1)
		account, err := repo.SignInEntra(ctx, first, false)
		require.NoError(t, err)
		require.Equal(t, "person@example.test", account.Username)
		require.Equal(t, first.ObjectID, *account.EntraObjectID)
		require.Equal(t, tenant, *account.EntraTenantID)
		first.UPN = "renamed@example.test"
		account, err = repo.SignInEntra(ctx, first, false)
		require.NoError(t, err)
		require.Equal(t, "person@example.test", account.Username)
		require.Equal(t, first.UPN, account.EntraUPN)
		_, err = repo.SignInEntra(ctx, identity(first.UPN, 2), false)
		require.ErrorIs(t, err, ErrIdentityDenied)
		_, err = repo.SignInEntra(ctx, identity("person@example.test", 2), false)
		require.ErrorIs(t, err, ErrIdentityDenied)
	})
	t.Run("does not link local accounts", func(t *testing.T) {
		local := models.AdminAccount{Username: "local@example.test", AuthSource: "local", PasswordHash: "preserved", Role: "viewer"}
		require.NoError(t, repo.CreateManagedAdmin(ctx, local, "test-admin"))
		_, err := repo.SignInEntra(ctx, identity(local.Username, 3), false)
		require.ErrorIs(t, err, ErrIdentityDenied)
		account, err := repo.GetAdmin(local.Username)
		require.NoError(t, err)
		require.Equal(t, "local", account.AuthSource)
		require.Equal(t, "preserved", account.PasswordHash)
		require.Nil(t, account.EntraObjectID)
	})
	t.Run("prebound accounts may retain the same display upn", func(t *testing.T) {
		for _, object := range []int{8, 9} {
			bound := identity("historical@example.test", object)
			require.NoError(t, repo.CreateManagedAdmin(
				ctx,
				models.AdminAccount{
					Username: fmt.Sprintf("historical-%d", object), AuthSource: "entra", Role: "viewer",
					EntraUPN: bound.UPN, EntraTenantID: &bound.TenantID, EntraObjectID: &bound.ObjectID,
				},
				"test-admin",
			))
			account, err := repo.SignInEntra(ctx, bound, false)
			require.NoError(t, err)
			require.Equal(t, fmt.Sprintf("historical-%d", object), account.Username)
		}
	})
	t.Run("ambiguous imported invitations fail closed", func(t *testing.T) {
		for _, username := range []string{"ambiguous-one", "ambiguous-two"} {
			_, err := repo.db.ExecContext(
				ctx,
				`INSERT INTO admins (username, password_hash, token, role, permissions, auth_source, entra_upn)
				VALUES ($1, '', '', 'viewer', 'gui_read', 'entra', 'ambiguous@example.test')`,
				username,
			)
			require.NoError(t, err)
		}
		_, err := repo.SignInEntra(ctx, identity("ambiguous@example.test", 10), true)
		require.ErrorIs(t, err, ErrIdentityDenied)
	})
	t.Run("preserves explicit role override on first binding", func(t *testing.T) {
		create(t, "override@example.test")
		require.NoError(t, repo.AssignAdminRole(
			ctx, models.AdminAccount{Username: "override@example.test", Role: "moderator", EntraRoleOverride: true}, "test-admin",
		))
		for range 2 {
			account, err := repo.SignInEntra(ctx, identity("override@example.test", 4), false)
			require.NoError(t, err)
			require.Equal(t, "moderator", account.Role)
		}
	})
	t.Run("rejects duplicate pending upns concurrently", func(t *testing.T) {
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, upn := range []string{"duplicate@example.test", "DUPLICATE@example.test"} {
			go func() {
				<-start
				results <- repo.CreateManagedAdmin(
					ctx, models.AdminAccount{Username: upn, AuthSource: "entra", Role: "viewer", EntraUPN: upn}, "test-admin",
				)
			}()
		}
		close(start)
		var successes, conflicts int
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, ErrIdentityConflict)
				conflicts++
			}
		}
		require.Equal(t, 1, successes)
		require.Equal(t, 1, conflicts)
	})
	t.Run("only one object can bind an invitation", func(t *testing.T) {
		create(t, "race@example.test")
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, object := range []int{5, 6} {
			go func() {
				<-start
				_, err := repo.SignInEntra(ctx, identity("race@example.test", object), false)
				results <- err
			}()
		}
		close(start)
		var successes, denied int
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, ErrIdentityDenied)
				denied++
			}
		}
		require.Equal(t, 1, successes)
		require.Equal(t, 1, denied)
	})
	t.Run("creation and automatic sign in cannot leave a duplicate invitation", func(t *testing.T) {
		const upn = "create-race@example.test"
		start := make(chan struct{})
		var wg sync.WaitGroup
		var createErr, signInErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			createErr = repo.CreateManagedAdmin(
				ctx, models.AdminAccount{Username: upn, AuthSource: "entra", Role: "viewer", EntraUPN: upn}, "test-admin",
			)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, signInErr = repo.SignInEntra(ctx, identity(upn, 7), true)
		}()
		close(start)
		wg.Wait()
		require.NoError(t, signInErr)
		if createErr != nil {
			require.ErrorIs(t, createErr, ErrIdentityConflict)
		}
		var count int
		require.NoError(t, repo.db.GetContext(
			context.Background(), &count, "SELECT count(*) FROM admins WHERE lower(entra_upn) = $1", upn,
		))
		require.Equal(t, 1, count)
	})
}
