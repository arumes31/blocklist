package api

import (
	"context"

	"blocklist/internal/models"
)

type IdentityRepositoryProvider interface {
	ListRoles(context.Context) ([]models.AccessRole, error)
	GetRole(context.Context, string) (*models.AccessRole, error)
	SaveRole(context.Context, models.AccessRole, string) error
	DeleteRole(context.Context, string, string, int) error
	CreateManagedAdminAtRevision(context.Context, models.AdminAccount, string, int) error
	CreateLegacyAdmin(context.Context, models.AdminAccount, string) error
	UpdateLegacyAdminPermissions(context.Context, models.AdminAccount, string, string) error
	AssignManagedAdminRole(context.Context, models.RoleAssignment) error
	ChangeManagedAdminPassword(context.Context, models.AdminMutation, string) error
	ResetManagedAdminTOTP(context.Context, models.AdminMutation) error
	DeleteManagedAdmin(context.Context, models.AdminMutation) error
	SetAdminDisabled(context.Context, models.AdminStatusChange) error
	SignInEntra(context.Context, models.EntraIdentity, bool) (*models.AdminAccount, error)
	ListLogs(context.Context, models.LogFilter) ([]models.AuditLog, int, error)
}
