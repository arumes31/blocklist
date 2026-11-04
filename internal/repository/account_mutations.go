package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"blocklist/internal/models"

	"github.com/jmoiron/sqlx"
)

// mutateManagedAccount runs write inside a transaction that holds the actor
// and target locks taken by lockManagedAccount, and records the audit entry in
// the same transaction. The change is rejected if the target no longer matches
// the snapshot the handler authorized.
func (p *PostgresRepository) mutateManagedAccount(
	ctx context.Context,
	change models.AdminMutation,
	action, reason string,
	write func(*sqlx.Tx, models.AdminAccount) error,
) error {
	if change.Expected.Username == "" || change.Expected.Username == change.RecoveryAdmin {
		return ErrIdentityDenied
	}
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting account change: %w", err)
	}
	defer rollbackIdentity(tx)

	_, current, err := lockManagedAccount(ctx, tx, change)
	if err != nil {
		return err
	}
	if err := write(tx, current); err != nil {
		return err
	}
	if err := auditIdentity(ctx, tx, change.Actor, action, current.Username, reason); err != nil {
		return fmt.Errorf("recording account change: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing account change: %w", err)
	}
	return nil
}

func execOne(ctx context.Context, tx *sqlx.Tx, query string, args ...any) error {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating account: %w", identityError(err))
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking account update: %w", err)
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// ChangeManagedAdminPassword replaces a local account's password and ends its
// sessions, provided the account is still the one that was authorized.
func (p *PostgresRepository) ChangeManagedAdminPassword(ctx context.Context, change models.AdminMutation, hash string) error {
	return p.mutateManagedAccount(ctx, change, "CHANGE_PASSWORD", "Admin password updated",
		func(tx *sqlx.Tx, current models.AdminAccount) error {
			if current.AuthSource == "entra" {
				return ErrIdentityDenied
			}
			return execOne(ctx, tx,
				"UPDATE admins SET password_hash = $1, session_version = session_version + 1 WHERE username = $2",
				hash, current.Username)
		})
}

// ResetManagedAdminTOTP clears a local account's authenticator so it must
// enroll again, provided the account is still the one that was authorized.
func (p *PostgresRepository) ResetManagedAdminTOTP(ctx context.Context, change models.AdminMutation) error {
	return p.mutateManagedAccount(ctx, change, "RESET_TOTP", "TOTP secret cleared, re-setup required on next login",
		func(tx *sqlx.Tx, current models.AdminAccount) error {
			if current.AuthSource == "entra" {
				return ErrIdentityDenied
			}
			return execOne(ctx, tx,
				"UPDATE admins SET token = '', session_version = session_version + 1 WHERE username = $1",
				current.Username)
		})
}

// DeleteManagedAdmin removes an account, provided it is still the one that
// was authorized.
func (p *PostgresRepository) DeleteManagedAdmin(ctx context.Context, change models.AdminMutation) error {
	if change.Expected.Username == change.Actor {
		return ErrIdentityDenied
	}
	return p.mutateManagedAccount(ctx, change, "DELETE_ADMIN", "User account and all associated tokens removed",
		func(tx *sqlx.Tx, current models.AdminAccount) error {
			return execOne(ctx, tx, "DELETE FROM admins WHERE username = $1", current.Username)
		})
}

// lockRoleRevision share-locks a role until commit and rejects it when its
// revision differs from the one that passed authorization.
func lockRoleRevision(ctx context.Context, tx *sqlx.Tx, roleID string, revision int) (models.AccessRole, error) {
	var role models.AccessRole
	err := tx.GetContext(ctx, &role,
		"SELECT id, permissions, revision FROM access_roles WHERE id = $1 FOR SHARE", roleID)
	if err != nil {
		return role, fmt.Errorf("locking role: %w", err)
	}
	if role.Revision != revision {
		return role, ErrIdentityConflict
	}
	return role, nil
}

// AssignManagedAdminRole grants the authorized role revision to the authorized target
// snapshot. The actor's authority over the role is rechecked under lock, and
// only an actor who may grant every permission may clear an Entra role
// override, because the next Entra sign-in then applies a directory-mapped
// role that was never checked against the actor.
func (p *PostgresRepository) AssignManagedAdminRole(ctx context.Context, assignment models.RoleAssignment) error {
	change := assignment.AdminMutation
	if change.Expected.Username == "" || change.Expected.Username == change.RecoveryAdmin {
		return ErrIdentityDenied
	}
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting role assignment: %w", err)
	}
	defer rollbackIdentity(tx)

	actor, current, err := lockManagedAccount(ctx, tx, change)
	if err != nil {
		return err
	}
	role, err := lockRoleRevision(ctx, tx, assignment.RoleID, assignment.RoleRevision)
	if err != nil {
		return err
	}
	if change.Actor != change.RecoveryAdmin {
		permissions := actorPermissions(actor, change.RecoveryAdmin)
		if !permissionsInclude(permissions, role.Permissions) {
			return ErrIdentityDenied
		}
		clearsOverride := current.AuthSource == "entra" && current.EntraRoleOverride && !assignment.Override
		if clearsOverride && !permissionsInclude(permissions, models.AllPermissions()) {
			return ErrIdentityDenied
		}
	}
	if err := execOne(ctx, tx, `UPDATE admins a SET role_id = r.id, role = r.id,
		permissions = r.permissions, entra_role_override = $3
		FROM access_roles r WHERE a.username = $1 AND r.id = $2`,
		current.Username, role.ID, assignment.Override,
	); err != nil {
		return err
	}
	if err := auditIdentity(ctx, tx, change.Actor, "ASSIGN_ROLE", current.Username, "Role: "+role.ID); err != nil {
		return fmt.Errorf("recording role assignment: %w", err)
	}
	return tx.Commit()
}

// permissionsInclude reports whether held contains every key in required.
func permissionsInclude(held, required string) bool {
	for _, key := range strings.Split(required, ",") {
		if key = strings.TrimSpace(key); key != "" && !models.HasPermission(held, key) {
			return false
		}
	}
	return true
}
