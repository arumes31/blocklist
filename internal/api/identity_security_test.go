package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type identityTestRepository struct{ IdentityRepositoryProvider }

func (identityTestRepository) ListRoles(context.Context) ([]models.AccessRole, error) {
	return nil, nil
}

func TestRoleBoundaries(t *testing.T) {
	read := "gui_read,view_ips,view_stats,view_audit_logs,view_event_logs,view_whitelist,view_excluded,view_settings,view_admins,view_roles,view_api_tokens,export_data"
	for _, role := range []struct{ name, permissions string }{
		{"viewer", read}, {"moderator", read + ",whitelist_ips,exclude_ips,unblock_ips"}, {"editor", models.AllPermissions()},
	} {
		for _, permission := range models.PermissionCatalog {
			t.Run(role.name+"/"+permission.Key, func(t *testing.T) {
				h, _, _, _, _ := setupTest()
				r := gin.New()
				r.Use(func(c *gin.Context) { c.Set("username", "member"); c.Set("permissions", role.permissions) })
				r.GET("/test", h.PermissionMiddleware(permission.Key), func(c *gin.Context) { c.Status(http.StatusNoContent) })
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))
				want := http.StatusForbidden
				if models.HasPermission(role.permissions, permission.Key) {
					want = http.StatusNoContent
				}
				require.Equal(t, want, w.Code)
			})
		}
	}
}

func TestLimitedRecoveryTokenCannotEscalate(t *testing.T) {
	h, _, _, _, _ := setupTest()
	for _, kind := range []string{"permission", "webhook", "create token", "update token", "sudo"} {
		t.Run(kind, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "admin")
			c.Set("permissions", "manage_api_tokens")
			c.Set("token_auth", true)
			c.Request = httptest.NewRequest("POST", "/test", strings.NewReader(`{"permissions":"manage_admins"}`))
			c.Request.Header.Set("Content-Type", "application/json")
			switch kind {
			case "permission":
				h.PermissionMiddleware("manage_admins")(c)
			case "webhook":
				require.False(t, h.checkWebhookPermissions(c, "admin", "block_ips"))
			case "create token":
				c.Request = httptest.NewRequest("POST", "/test", strings.NewReader("name=test&permissions=manage_admins"))
				c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				h.CreateAPIToken(c)
			case "update token":
				c.Params = gin.Params{{Key: "id", Value: "1"}}
				h.UpdateAPITokenPermissions(c)
			case "sudo":
				h.SudoMiddleware()(c)
			}
			require.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestDelegatedAccountManagerCannotTakeOverEditor(t *testing.T) {
	for _, action := range []string{"password", "mfa", "delete", "role", "legacy permissions"} {
		t.Run(action, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			h.identityRepo = identityTestRepository{}
			pg.On("GetAdmin", "editor").Return(&models.AdminAccount{Username: "editor", AuthSource: "local", Permissions: models.AllPermissions()}, nil).Maybe()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "limited-manager")
			c.Set("permissions", "gui_read,manage_admins")
			c.Request = httptest.NewRequest("POST", "/test", strings.NewReader(`{"username":"editor","new_password":"synthetic-password","role":"viewer","permissions":"manage_admins"}`))
			c.Request.Header.Set("Content-Type", "application/json")
			switch action {
			case "password":
				h.ChangeAdminPassword(c)
			case "mfa":
				h.ChangeAdminTOTP(c)
			case "delete":
				h.DeleteAdmin(c)
			case "role":
				h.ChangeAdminRole(c)
			case "legacy permissions":
				h.ChangeAdminPermissions(c)
			}
			require.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestSessionUsesCurrentPermissions(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	h.identityRepo = identityTestRepository{}
	pg.On("GetAdmin", "member").Return(&models.AdminAccount{Username: "member", Permissions: "gui_read,view_ips", SessionVersion: 1}, nil)
	r := gin.New()
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-test-session-key"))))
	r.Use(func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("logged_in", true)
		s.Set("username", "member")
		s.Set("client_ip", "127.0.0.1")
		s.Set("permissions", models.AllPermissions())
		s.Set("session_version", 1)
		s.Set("sudo_time", time.Now().Unix())
	})
	r.GET("/test", h.AuthMiddleware(), h.PermissionMiddleware("manage_admins"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	pg.AssertCalled(t, "GetAdmin", "member")
}

func TestBearerPermissionsRespectOwnerRole(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	h.identityRepo = identityTestRepository{}
	pg.On("GetAPITokenByHash", mock.Anything).Return(&models.APIToken{ID: 1, Username: "member", Permissions: "view_ips,manage_roles"}, nil)
	pg.On("UpdateTokenLastUsed", 1, mock.Anything).Return(nil)
	pg.On("GetAdmin", "member").Return(&models.AdminAccount{Username: "member", Permissions: "gui_read,view_ips"}, nil)
	r := gin.New()
	r.GET("/test", h.AuthMiddleware(), h.PermissionMiddleware("manage_roles"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer synthetic-token")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestEntraAccountRejectsPendingLocalEnrollment(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	pg.On("GetAdmin", "entra-user").Return(&models.AdminAccount{Username: "entra-user", AuthSource: "entra"}, nil)
	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-test-session-key"))))
	r.POST("/login", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("pending_auth_user", "entra-user")
		s.Set("pending_auth_verified", true)
		s.Set("pending_totp_secret", "JBSWY3DPEHPK3PXP")
		h.Login(c)
	})
	form := url.Values{"username": {"entra-user"}, "setup_secret": {"JBSWY3DPEHPK3PXP"}, "totp": {"123456"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	pg.AssertNotCalled(t, "UpdateAdminToken", mock.Anything, mock.Anything)
}
