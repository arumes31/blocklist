package repository

import (
	"context"
	"database/sql"
	"fmt"

	"blocklist/internal/models"

	"github.com/jmoiron/sqlx"
)

// SetAdminDisabled changes access and invalidates sessions in the audit transaction.
// It rejects stale snapshots and rechecks the actor's current authority under locks.
func (p *PostgresRepository) SetAdminDisabled(ctx context.Context, change models.AdminStatusChange) error {
	if change.Expected.Username == change.RecoveryAdmin || change.Expected.Username == change.Actor {
		return ErrIdentityDenied
	}
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting account status change: %w", err)
	}
	defer rollbackIdentity(tx)

	_, current, err := lockManagedAccount(ctx, tx, models.AdminMutation{
		Expected: change.Expected, Actor: change.Actor, RecoveryAdmin: change.RecoveryAdmin,
	})
	if err != nil {
		return err
	}
	if current.Disabled != change.Expected.Disabled {
		return ErrIdentityConflict
	}
	if current.Disabled == change.Disabled {
		return nil
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE admins SET disabled = $2, session_version = session_version + 1 WHERE username = $1`,
		current.Username,
		change.Disabled,
	)
	if err != nil {
		return fmt.Errorf("updating account status: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking account status update: %w", err)
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	action := "ENABLE_ADMIN"
	if change.Disabled {
		action = "DISABLE_ADMIN"
	}
	if err := auditIdentity(
		ctx,
		tx,
		change.Actor,
		action,
		current.Username,
		"Account access changed; sessions invalidated",
	); err != nil {
		return fmt.Errorf("recording account status change: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing account status change: %w", err)
	}
	return nil
}

// lockManagedAccount locks the actor and the target account (and their roles)
// for the rest of the transaction, rechecks that the actor may still manage
// the target, and rejects the change when the target no longer matches the
// snapshot that passed authorization in the handler.
func lockManagedAccount(ctx context.Context, tx *sqlx.Tx, change models.AdminMutation) (actor, current models.AdminAccount, err error) {
	// Lock actor and target in a stable order. Concurrent administrators cannot
	// act on each other using authorizations obtained before either changed.
	accounts := []models.AdminAccount{}
	err = tx.SelectContext(
		ctx,
		&accounts,
		`SELECT username, permissions, role_id, auth_source, session_version, disabled, entra_role_override
		FROM admins WHERE username IN ($1, $2) ORDER BY username FOR NO KEY UPDATE`,
		change.Actor,
		change.Expected.Username,
	)
	if err != nil {
		return models.AdminAccount{}, models.AdminAccount{}, fmt.Errorf("locking managed account: %w", err)
	}
	want := 2
	if change.Actor == change.Expected.Username {
		want = 1
	}
	if len(accounts) != want {
		return models.AdminAccount{}, models.AdminAccount{}, sql.ErrNoRows
	}
	for i := range accounts {
		account := &accounts[i]
		// As with individual permissions, a role edit does not bump session_version.
		// Lock roles separately, allowing role-deletion foreign-key KEY SHARE checks.
		if account.RoleID != nil {
			if err := tx.GetContext(
				ctx,
				&account.Permissions,
				"SELECT permissions FROM access_roles WHERE id = $1 FOR SHARE",
				*account.RoleID,
			); err != nil {
				return models.AdminAccount{}, models.AdminAccount{}, fmt.Errorf("locking managed account role: %w", err)
			}
		}
		if account.Username == change.Actor {
			actor = *account
		}
		if account.Username == change.Expected.Username {
			current = *account
		}
	}
	if actor.Disabled {
		return models.AdminAccount{}, models.AdminAccount{}, ErrIdentityDenied
	}
	permissions := actorPermissions(actor, change.RecoveryAdmin)
	if !models.HasPermission(permissions, "manage_admins") {
		return models.AdminAccount{}, models.AdminAccount{}, ErrIdentityDenied
	}
	if actor.Username != change.RecoveryAdmin && !models.PermissionsCoverAccount(permissions, current) {
		return models.AdminAccount{}, models.AdminAccount{}, ErrIdentityDenied
	}
	expected := change.Expected
	sameRole := current.RoleID == nil && expected.RoleID == nil
	if current.RoleID != nil && expected.RoleID != nil {
		sameRole = *current.RoleID == *expected.RoleID
	}
	changedAccess := !sameRole || current.Permissions != expected.Permissions
	changedIdentity := current.SessionVersion != expected.SessionVersion || current.AuthSource != expected.AuthSource
	if changedAccess || changedIdentity || current.EntraRoleOverride != expected.EntraRoleOverride {
		return models.AdminAccount{}, models.AdminAccount{}, ErrIdentityConflict
	}
	return actor, current, nil
}

// actorPermissions returns the effective permissions of a locked actor row.
func actorPermissions(actor models.AdminAccount, recoveryAdmin string) string {
	if actor.Username == recoveryAdmin {
		return models.AllPermissions()
	}
	return models.WorkspacePermissions(actor)
}
