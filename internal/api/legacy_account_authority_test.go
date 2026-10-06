package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestLegacyAccountManagement(t *testing.T) {
	for _, tc := range []struct {
		name, actor, permissions, targetPermissions string
		token                                       bool
		status                                      int
	}{
		{
			name: "Entra editor can migrate retired legacy permissions", actor: "entra-editor",
			permissions: models.AllPermissions(), targetPermissions: "gui_read,gui_write,webhook_access,view_ips",
			status: http.StatusOK,
		},
		{
			name: "recovery can manage every legacy snapshot", actor: "admin",
			permissions: models.AllPermissions(), targetPermissions: "gui_read,gui_write,webhook_access,unknown_legacy_key",
			status: http.StatusOK,
		},
		{
			name: "delegated manager still needs live capabilities", actor: "manager",
			permissions: "gui_read,manage_admins", targetPermissions: "gui_read,gui_write,manage_roles",
			status: http.StatusForbidden,
		},
		{
			name: "unknown capabilities fail closed for editors", actor: "entra-editor",
			permissions: models.AllPermissions(), targetPermissions: "gui_read,unknown_permission",
			status: http.StatusForbidden,
		},
		{
			name: "recovery token has no recovery bypass", actor: "admin", token: true,
			permissions: "gui_read,manage_admins", targetPermissions: "gui_read,manage_roles",
			status: http.StatusForbidden,
		},
	} {
		for _, action := range []string{"role", "status"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				h, _, pg, _, _ := setupTest()
				roleRepo := &roleUIRepository{roleMutationRepository: roleMutationRepository{
					role: models.AccessRole{ID: "moderator", Permissions: "gui_read,unblock_ips"},
				}}
				statusRepo := &accountStatusRepository{}
				h.identityRepo = roleRepo
				body := `{"username":"legacy","role":"moderator"}`
				if action == "status" {
					h.identityRepo = statusRepo
					body = `{"username":"legacy","disabled":true}`
				}
				pg.On("GetAdmin", "legacy").Return(&models.AdminAccount{
					Username: "legacy", AuthSource: "local", Permissions: tc.targetPermissions,
				}, nil).Once()
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Set("username", tc.actor)
				c.Set("permissions", tc.permissions)
				c.Set("token_auth", tc.token)
				c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/change_"+action, strings.NewReader(body))
				c.Request.Header.Set("Content-Type", "application/json")
				if action == "role" {
					h.ChangeAdminRole(c)
					require.Equal(t, tc.status == http.StatusOK, roleRepo.assigned != nil)
				} else {
					h.ChangeAdminStatus(c)
					require.Equal(t, tc.status == http.StatusOK, statusRepo.change != nil)
				}
				require.Equal(t, tc.status, w.Code, w.Body.String())
				pg.AssertExpectations(t)
			})
		}
	}
}
