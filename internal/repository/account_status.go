package repository

import (
	"context"
	"database/sql"
	"fmt"

	"blocklist/internal/models"
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

	// Lock actor and target in a stable order. Concurrent administrators cannot
	// disable each other using authorizations obtained before either was disabled.
	accounts := []models.AdminAccount{}
	err = tx.SelectContext(
		ctx,
		&accounts,
		`SELECT username, permissions, role_id, auth_source, session_version, disabled
		FROM admins WHERE username IN ($1, $2) ORDER BY username FOR NO KEY UPDATE`,
		change.Actor,
		change.Expected.Username,
	)
	if err != nil {
		return fmt.Errorf("locking account status: %w", err)
	}
	if len(accounts) != 2 {
		return sql.ErrNoRows
	}
	var actor, current models.AdminAccount
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
				return fmt.Errorf("locking account status role: %w", err)
			}
		}
		if account.Username == change.Actor {
			actor = *account
		} else {
			current = *account
		}
	}
	if actor.Disabled {
		return ErrIdentityDenied
	}
	permissions := models.WorkspacePermissions(actor)
	if actor.Username == change.RecoveryAdmin {
		permissions = models.AllPermissions()
	}
	if !models.HasPermission(permissions, "manage_admins") {
		return ErrIdentityDenied
	}
	if actor.Username != change.RecoveryAdmin && !models.PermissionsCoverAccount(permissions, current) {
		return ErrIdentityDenied
	}
	expected := change.Expected
	sameRole := current.RoleID == nil && expected.RoleID == nil
	if current.RoleID != nil && expected.RoleID != nil {
		sameRole = *current.RoleID == *expected.RoleID
	}
	changedAccess := !sameRole || current.Permissions != expected.Permissions
	changedIdentity := current.SessionVersion != expected.SessionVersion || current.AuthSource != expected.AuthSource
	if changedAccess || changedIdentity || current.Disabled != expected.Disabled {
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
