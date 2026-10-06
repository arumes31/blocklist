package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type legacyAccountTestRepository struct {
	managedAccountTestRepository
	legacyCreated bool
	updated       bool
	expected      models.AdminAccount
	permissions   string
	updateErr     error
}

func (r *legacyAccountTestRepository) CreateLegacyAdmin(
	_ context.Context,
	account models.AdminAccount,
	_ string,
) error {
	r.legacyCreated = true
	r.created = &account
	return r.err
}

func (r *legacyAccountTestRepository) UpdateLegacyAdminPermissions(
	_ context.Context,
	expected models.AdminAccount,
	permissions string,
	_ string,
) error {
	r.expected, r.permissions = expected, permissions
	if r.updateErr != nil {
		return r.updateErr
	}
	r.updated = true
	return nil
}

func TestLegacyAccountCreationCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, body, actorPermissions string
		status                       int
		legacy                       bool
		role, permissions            string
	}{
		{
			name: "old operator payload",
			body: `{"username":"member","password":"old-pass","role":"operator",
				"permissions":"gui_read,view_ips"}`,
			status: 200, legacy: true, role: "operator", permissions: "gui_read,view_ips",
		},
		{
			name: "old defaults", body: `{"username":"member","password":"old-pass"}`,
			status: 200, legacy: true, role: "operator", permissions: "gui_read",
		},
		{
			name:   "old arbitrary label",
			body:   `{"username":"member","password":"old-pass","role":"custom-operator","permissions":"gui_read"}`,
			status: 200, legacy: true, role: "custom-operator", permissions: "gui_read",
		},
		{
			name:   "managed UI unchanged",
			body:   `{"username":"member","password":"modern-password","auth_source":"local","role":"viewer"}`,
			status: 200, role: "viewer",
		},
		{
			name:             "cannot grant extra permissions",
			body:             `{"username":"member","password":"old-pass","permissions":"manage_roles"}`,
			actorPermissions: "gui_read,manage_admins", status: 403,
		},
		{
			name:             "cannot grant implicit saved view rights",
			body:             `{"username":"member","password":"old-pass","permissions":"gui_read,view_ips"}`,
			actorPermissions: "gui_read,view_ips,view_audit_logs,view_event_logs,manage_admins", status: 403,
		},
		{name: "cannot replace recovery admin", body: `{"username":"admin","password":"old-pass"}`, status: 400},
		{
			name: "unknown permission rejected",
			body: `{"username":"member","password":"old-pass","permissions":"superuser"}`, status: 400,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _, auth, _ := setupTest()
			repo := &legacyAccountTestRepository{}
			h.identityRepo = repo
			auth.On("HashPassword", mock.Anything).Return("synthetic-hash", nil).Maybe()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "manager")
			permissions := tc.actorPermissions
			if permissions == "" {
				permissions = models.AllPermissions()
			}
			c.Set("permissions", permissions)
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/create", strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")
			h.CreateAdmin(c)
			require.Equal(
				t,
				tc.status,
				w.Code,
				w.Body.String(),
			)
			if tc.status != http.StatusOK {
				require.Nil(t, repo.created)
				return
			}
			require.Equal(t, tc.legacy, repo.legacyCreated)
			require.Equal(t, tc.role, repo.created.Role)
			if tc.legacy {
				require.Equal(t, tc.permissions, repo.created.Permissions)
				require.Nil(t, repo.created.RoleID)
				require.Equal(t, "local", repo.created.AuthSource)
			}
		})
	}
}

func TestLegacyAccountPermissionUpdateCompatibility(t *testing.T) {
	viewer := "viewer"
	for _, tc := range []struct {
		name, actorPermissions, next string
		account                      models.AdminAccount
		readErr, updateErr           error
		status                       int
	}{
		{
			name: "legacy update", account: models.AdminAccount{Permissions: "gui_read,view_ips", AuthSource: "local"},
			next: "gui_read", status: 200,
		},
		{name: "empty permissions revoke access", account: models.AdminAccount{Permissions: "gui_read"}, status: 200},
		{
			name:    "managed account becomes individual",
			account: models.AdminAccount{RoleID: &viewer, Permissions: "gui_read,view_ips", AuthSource: "local"},
			next:    "gui_read", status: 200,
		},
		{
			name: "cannot strip privileged target", account: models.AdminAccount{Permissions: models.AllPermissions()},
			actorPermissions: "gui_read,manage_admins", next: "gui_read", status: 403,
		},
		{
			name: "cannot grant extra permission", account: models.AdminAccount{Permissions: "gui_read"},
			actorPermissions: "gui_read,manage_admins", next: "manage_roles", status: 403,
		},
		{
			name:             "cannot gain implied write via detach",
			account:          models.AdminAccount{RoleID: &viewer, Permissions: "gui_read,view_ips"},
			actorPermissions: "gui_read,view_ips,view_audit_logs,view_event_logs,manage_admins",
			next:             "gui_read,view_ips", status: 403,
		},
		{name: "missing account", readErr: sql.ErrNoRows, next: "gui_read", status: 404},
		{
			name: "changed authorization snapshot", account: models.AdminAccount{Permissions: "gui_read"},
			updateErr: repository.ErrIdentityConflict, next: "gui_read", status: 409,
		},
		{
			name:    "entra remains role managed",
			account: models.AdminAccount{AuthSource: "entra", RoleID: &viewer, Permissions: "gui_read"},
			next:    "gui_read", status: 409,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			repo := &legacyAccountTestRepository{updateErr: tc.updateErr}
			h.identityRepo = repo
			tc.account.Username, tc.account.SessionVersion = "member", 7
			pg.On("GetAdmin", "member").Return(&tc.account, tc.readErr).Maybe()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "manager")
			permissions := tc.actorPermissions
			if permissions == "" {
				permissions = models.AllPermissions()
			}
			c.Set("permissions", permissions)
			body := `{"username":"member","permissions":"` + tc.next + `"}`
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/change_permissions", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")
			h.ChangeAdminPermissions(c)
			require.Equal(
				t,
				tc.status,
				w.Code,
				w.Body.String(),
			)
			require.Equal(t, tc.status == http.StatusOK, repo.updated)
			if repo.updated {
				require.Equal(t, tc.account, repo.expected)
				require.Equal(t, tc.next, repo.permissions)
			}
			pg.AssertNotCalled(t, "UpdateAdminPermissions", mock.Anything, mock.Anything)
		})
	}
}
