package repository

import (
	"context"
	"database/sql"
	"fmt"

	"blocklist/internal/models"
)

func (p *PostgresRepository) CreateLegacyAdmin(ctx context.Context, account models.AdminAccount, actor string) error {
	if account.AuthSource != "local" || account.RoleID != nil {
		return ErrIdentityDenied
	}
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting legacy account creation: %w", err)
	}
	defer rollbackIdentity(tx)
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO admins (username, password_hash, token, role, permissions, session_version, auth_source)
		VALUES ($1, $2, '', $3, $4, 1, 'local')`,
		account.Username,
		account.PasswordHash,
		account.Role,
		account.Permissions,
	)
	if err != nil {
		return fmt.Errorf("creating legacy account: %w", identityError(err))
	}
	if err := auditIdentity(
		ctx,
		tx,
		actor,
		"CREATE_ADMIN",
		account.Username,
		"Legacy role: "+account.Role+"; permissions: "+account.Permissions,
	); err != nil {
		return fmt.Errorf("recording legacy account creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing legacy account creation: %w", err)
	}
	return nil
}

func (p *PostgresRepository) UpdateLegacyAdminPermissions(
	ctx context.Context,
	expected models.AdminAccount,
	permissions, actor string,
) error {
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting legacy permission update: %w", err)
	}
	defer rollbackIdentity(tx)
	var current models.AdminAccount
	// Do not block the KEY SHARE lock used by role-deletion FK checks while
	// waiting for the role below. We do not update this account's primary key.
	if err := tx.GetContext(
		ctx,
		&current,
		`SELECT username, permissions, role_id, auth_source, session_version
		FROM admins WHERE username = $1 FOR NO KEY UPDATE`,
		expected.Username,
	); err != nil {
		return fmt.Errorf("locking legacy account: %w", err)
	}
	if current.AuthSource != "local" {
		return ErrIdentityDenied
	}
	if current.RoleID != nil {
		// Lock the role separately: role edits do not increment session_version,
		// and a LEFT JOIN cannot lock the nullable role side with FOR SHARE.
		if err := tx.GetContext(
			ctx,
			&current.Permissions,
			"SELECT permissions FROM access_roles WHERE id = $1 FOR SHARE",
			*current.RoleID,
		); err != nil {
			return fmt.Errorf("locking current account role: %w", err)
		}
	}
	sameRole := current.RoleID == nil && expected.RoleID == nil
	if current.RoleID != nil && expected.RoleID != nil {
		sameRole = *current.RoleID == *expected.RoleID
	}
	changedPermissions := !sameRole || current.Permissions != expected.Permissions
	changedAccount := current.SessionVersion != expected.SessionVersion || current.AuthSource != expected.AuthSource
	if changedPermissions || changedAccount {
		return ErrIdentityConflict
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE admins SET permissions = $2, role_id = NULL, session_version = session_version + 1
		WHERE username = $1`,
		expected.Username,
		permissions,
	)
	if err != nil {
		return fmt.Errorf("updating individual permissions: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking individual permission update: %w", err)
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	if err := auditIdentity(
		ctx,
		tx,
		actor,
		"CHANGE_PERMISSIONS",
		expected.Username,
		fmt.Sprintf("From [%s] to [%s]; individual permissions", current.Permissions, permissions),
	); err != nil {
		return fmt.Errorf("recording individual permission update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing individual permission update: %w", err)
	}
	return nil
}
