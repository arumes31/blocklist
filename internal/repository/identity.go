package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"blocklist/internal/models"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jmoiron/sqlx"
	zlog "github.com/rs/zerolog/log"
)

var (
	ErrIdentityConflict = errors.New("identity: record changed or already exists")
	ErrRoleInUse        = errors.New("identity: role is assigned to accounts")
	ErrRoleProtected    = errors.New("identity: built-in roles cannot be deleted")
	ErrIdentityDenied   = errors.New("identity: account is not provisioned for this identity")
)

// Security-sensitive reads use the primary, never a potentially stale replica.
const adminSelect = `SELECT a.username, a.password_hash, a.token,
	COALESCE(r.id, a.role) AS role, COALESCE(r.permissions, a.permissions) AS permissions,
	a.session_version, a.role_id, a.auth_source, a.entra_tenant_id, a.entra_object_id,
	a.entra_upn, a.entra_role_override, a.disabled
	FROM admins a LEFT JOIN access_roles r ON r.id = a.role_id`

func rollbackIdentity(tx *sqlx.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		zlog.Error().Err(err).Msg("Failed to roll back identity transaction")
	}
}

func identityError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrIdentityConflict
		case "23503":
			return ErrRoleInUse
		}
	}
	return err
}

func auditIdentity(ctx context.Context, tx *sqlx.Tx, actor, action, target, reason string) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO audit_logs (actor, action, target, reason) VALUES ($1, $2, $3, $4)",
		actor, action, target, reason,
	)
	return err
}

func (p *PostgresRepository) ListRoles(ctx context.Context) ([]models.AccessRole, error) {
	roles := []models.AccessRole{}
	err := p.db.SelectContext(ctx, &roles, `SELECT r.id, r.name, r.description, r.permissions,
		r.is_builtin, r.revision, (SELECT count(*) FROM admins a WHERE a.role_id = r.id) AS member_count
		FROM access_roles r ORDER BY r.is_builtin DESC, lower(r.name)`)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	return roles, nil
}

func (p *PostgresRepository) GetRole(ctx context.Context, id string) (*models.AccessRole, error) {
	var role models.AccessRole
	err := p.db.GetContext(ctx, &role,
		"SELECT id, name, description, permissions, is_builtin, revision FROM access_roles WHERE id = $1", id)
	if err != nil {
		return nil, fmt.Errorf("reading role: %w", err)
	}
	return &role, nil
}

func (p *PostgresRepository) SaveRole(ctx context.Context, role models.AccessRole, actor string) error {
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting role transaction: %w", err)
	}
	defer rollbackIdentity(tx)
	action := "CREATE_ROLE"
	if role.Revision == 0 {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO access_roles (id, name, description, permissions) VALUES ($1, $2, $3, $4)",
			role.ID, role.Name, role.Description, role.Permissions,
		)
	} else {
		action = "UPDATE_ROLE"
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE access_roles SET name = $1, description = $2,
			permissions = $3, revision = revision + 1, updated_at = CURRENT_TIMESTAMP
			WHERE id = $4 AND revision = $5`,
			role.Name, role.Description, role.Permissions, role.ID, role.Revision,
		)
		if err == nil {
			changed, countErr := result.RowsAffected()
			if countErr != nil {
				return fmt.Errorf("checking role update: %w", countErr)
			}
			if changed != 1 {
				return ErrIdentityConflict
			}
		}
	}
	if err != nil {
		return fmt.Errorf("saving role: %w", identityError(err))
	}
	if err := auditIdentity(ctx, tx, actor, action, role.ID, role.Permissions); err != nil {
		return fmt.Errorf("recording role change: %w", err)
	}
	return tx.Commit()
}

func (p *PostgresRepository) DeleteRole(ctx context.Context, id, actor string, expectedRevision int) error {
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting role deletion: %w", err)
	}
	defer rollbackIdentity(tx)
	var role models.AccessRole
	if err := tx.GetContext(
		ctx,
		&role,
		"SELECT is_builtin, revision FROM access_roles WHERE id = $1 FOR UPDATE",
		id,
	); err != nil {
		return fmt.Errorf("reading role for deletion: %w", err)
	}
	if role.IsBuiltin {
		return ErrRoleProtected
	}
	// The handler authorized the stored permissions at this revision. Do not
	// delete a role whose permissions changed between that read and this lock.
	if expectedRevision < 1 || role.Revision != expectedRevision {
		return ErrIdentityConflict
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM access_roles WHERE id = $1", id); err != nil {
		return fmt.Errorf("deleting role: %w", identityError(err))
	}
	if err := auditIdentity(ctx, tx, actor, "DELETE_ROLE", id, "Role removed"); err != nil {
		return fmt.Errorf("recording role deletion: %w", err)
	}
	return tx.Commit()
}

func (p *PostgresRepository) CreateManagedAdmin(ctx context.Context, admin models.AdminAccount, actor string) error {
	if admin.AuthSource == "entra" && admin.EntraObjectID == nil {
		upn, err := models.NormalizeEntraUPN(admin.EntraUPN)
		if err != nil || admin.EntraTenantID != nil {
			return ErrIdentityDenied
		}
		admin.EntraUPN = upn
	}
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting account creation: %w", err)
	}
	defer rollbackIdentity(tx)
	if admin.AuthSource == "entra" && admin.EntraUPN != "" {
		if err := lockEntraUPN(ctx, tx, admin.EntraUPN); err != nil {
			return err
		}
		var exists bool
		err := tx.GetContext(
			ctx,
			&exists,
			`SELECT EXISTS (SELECT 1 FROM admins WHERE auth_source = 'entra'
			AND lower(btrim(entra_upn)) = lower(btrim($1))
			AND ($2 OR entra_object_id IS NULL))`,
			admin.EntraUPN,
			admin.EntraObjectID == nil,
		)
		if err != nil {
			return fmt.Errorf("checking entra invitation: %w", err)
		}
		if exists {
			return ErrIdentityConflict
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO admins
		(username, password_hash, token, role, permissions, session_version, role_id, auth_source, entra_upn, entra_tenant_id, entra_object_id)
		SELECT $1, $2, '', id, permissions, 1, id, $4, $5, $6, $7 FROM access_roles WHERE id = $3`,
		admin.Username, admin.PasswordHash, admin.Role, admin.AuthSource, admin.EntraUPN, admin.EntraTenantID, admin.EntraObjectID,
	)
	if err != nil {
		return fmt.Errorf("creating account: %w", identityError(err))
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking new account: %w", err)
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	if err := auditIdentity(ctx, tx, actor, "CREATE_ADMIN", admin.Username, "Role: "+admin.Role+"; source: "+admin.AuthSource); err != nil {
		return fmt.Errorf("recording account creation: %w", err)
	}
	return tx.Commit()
}

func (p *PostgresRepository) AssignAdminRole(ctx context.Context, admin models.AdminAccount, actor string) error {
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting role assignment: %w", err)
	}
	defer rollbackIdentity(tx)
	result, err := tx.ExecContext(ctx, `UPDATE admins a SET role_id = r.id, role = r.id,
		permissions = r.permissions, entra_role_override = $3
		FROM access_roles r WHERE a.username = $1 AND r.id = $2`,
		admin.Username, admin.Role, admin.EntraRoleOverride,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking role assignment: %w", err)
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	if err := auditIdentity(ctx, tx, actor, "ASSIGN_ROLE", admin.Username, "Role: "+admin.Role); err != nil {
		return fmt.Errorf("recording role assignment: %w", err)
	}
	return tx.Commit()
}

// SignInEntra accepts a verified, tenant- and app-role-validated identity.
// Only an unbound Entra invitation may match by UPN, once. Bound and local
// accounts never link by UPN. Automatic provisioning remains opt-in.
func (p *PostgresRepository) SignInEntra(ctx context.Context, identity models.EntraIdentity, autoProvision bool) (*models.AdminAccount, error) {
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting entra sign-in: %w", err)
	}
	defer rollbackIdentity(tx)
	// Serialize first sign-ins for this immutable identity across app replicas.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", identity.TenantID+":"+identity.ObjectID); err != nil {
		return nil, fmt.Errorf("locking entra identity: %w", err)
	}
	upn, upnErr := models.NormalizeEntraUPN(identity.UPN)
	if upnErr == nil {
		if err := lockEntraUPN(ctx, tx, upn); err != nil {
			return nil, err
		}
	}
	var admin models.AdminAccount
	err = tx.GetContext(ctx, &admin, adminSelect+` WHERE a.auth_source = 'entra'
		AND a.entra_tenant_id = $1 AND a.entra_object_id = $2 FOR UPDATE OF a`, identity.TenantID, identity.ObjectID)
	if errors.Is(err, sql.ErrNoRows) && upnErr == nil {
		candidates := []models.AdminAccount{}
		err = tx.SelectContext(
			ctx,
			&candidates,
			adminSelect+` WHERE a.auth_source = 'entra'
			AND a.entra_tenant_id IS NULL AND a.entra_object_id IS NULL
			AND lower(btrim(a.entra_upn)) = $1 LIMIT 2 FOR UPDATE OF a`,
			upn,
		)
		if err != nil {
			return nil, fmt.Errorf("reading entra invitation: %w", err)
		}
		switch len(candidates) {
		case 0:
			err = sql.ErrNoRows
		case 1:
			admin = candidates[0]
		default:
			return nil, ErrIdentityDenied // Never choose between ambiguous invitations.
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		if !autoProvision || identity.UPN == "" {
			return nil, ErrIdentityDenied
		}
		// The immutable name prevents a reused UPN from taking over an old account.
		admin.Username = "entra:" + identity.TenantID + ":" + identity.ObjectID
		_, err = tx.ExecContext(ctx, `INSERT INTO admins
			(username, password_hash, token, role, permissions, session_version, role_id, auth_source)
			SELECT $1, '', '', id, permissions, 1, id, 'entra' FROM access_roles WHERE id = $2`,
			admin.Username, identity.RoleID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving entra account: %w", identityError(err))
	}
	if admin.Disabled {
		return nil, ErrIdentityDenied
	}
	if admin.EntraRoleOverride && admin.RoleID != nil {
		identity.RoleID = *admin.RoleID
	}
	result, err := tx.ExecContext(ctx, `UPDATE admins a SET entra_tenant_id = $2, entra_object_id = $3,
		entra_upn = $4, role_id = r.id, role = r.id, permissions = r.permissions
		FROM access_roles r WHERE a.username = $1 AND r.id = $5 AND a.auth_source = 'entra'
		AND ((a.entra_tenant_id IS NULL AND a.entra_object_id IS NULL)
		OR (a.entra_tenant_id = $2 AND a.entra_object_id = $3))`,
		admin.Username, identity.TenantID, identity.ObjectID, strings.TrimSpace(identity.UPN), identity.RoleID,
	)
	if err != nil {
		return nil, fmt.Errorf("binding entra identity: %w", identityError(err))
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return nil, ErrIdentityDenied
	}
	if err := auditIdentity(ctx, tx, admin.Username, "ENTRA_LOGIN_SUCCESS", "REDACTED", "App role: "+identity.RoleID); err != nil {
		return nil, fmt.Errorf("recording entra sign-in: %w", err)
	}
	if err := tx.GetContext(ctx, &admin, adminSelect+" WHERE a.username = $1", admin.Username); err != nil {
		return nil, fmt.Errorf("reading signed-in account: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing entra sign-in: %w", err)
	}
	return &admin, nil
}

// The shared transaction lock protects invitation checks even when no row exists.
func lockEntraUPN(ctx context.Context, tx *sqlx.Tx, upn string) error {
	_, err := tx.ExecContext(
		ctx,
		"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
		"entra:upn:"+strings.ToLower(strings.TrimSpace(upn)),
	)
	if err != nil {
		return fmt.Errorf("locking entra invitation: %w", err)
	}
	return nil
}
