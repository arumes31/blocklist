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
	CreateManagedAdmin(context.Context, models.AdminAccount, string) error
	CreateLegacyAdmin(context.Context, models.AdminAccount, string) error
	UpdateLegacyAdminPermissions(context.Context, models.AdminAccount, string, string) error
	AssignAdminRole(context.Context, models.AdminAccount, string) error
	SignInEntra(context.Context, models.EntraIdentity, bool) (*models.AdminAccount, error)
	ListLogs(context.Context, models.LogFilter) ([]models.AuditLog, int, error)
}
