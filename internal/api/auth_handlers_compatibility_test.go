package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceCompatibility(t *testing.T) {
	managedRole := "viewer"
	for _, tc := range []struct {
		name      string
		account   models.AdminAccount
		wantAudit bool
		wantViews bool
	}{
		{
			name: "legacy local", account: models.AdminAccount{AuthSource: "local", Permissions: "gui_read,view_ips"},
			wantAudit: true, wantViews: true,
		},
		{
			name: "legacy empty source", account: models.AdminAccount{Permissions: "gui_read,view_ips"},
			wantAudit: true, wantViews: true,
		},
		{name: "no old entitlement", account: models.AdminAccount{Permissions: "gui_read"}},
		{
			name: "managed viewer remains read only",
			account: models.AdminAccount{
				RoleID: &managedRole, AuthSource: "local", Permissions: "gui_read,view_ips,view_audit_logs,view_event_logs",
			},
			wantAudit: true,
		},
		{
			name:    "entra never receives legacy rights",
			account: models.AdminAccount{AuthSource: "entra", Permissions: "gui_read,view_ips"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, permission := range []string{"view_audit_logs", "view_event_logs", "manage_views"} {
				t.Run(permission, func(t *testing.T) {
					h, _, pg, _, _ := setupTest()
					h.identityRepo = identityTestRepository{}
					tc.account.Username = "member"
					pg.On("GetAdmin", "member").Return(&tc.account, nil)
					r := gin.New()
					r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-session-key"))))
					r.Use(func(c *gin.Context) {
						s := sessions.Default(c)
						s.Set("logged_in", true)
						s.Set("username", "member")
						s.Set("client_ip", "127.0.0.1")
					})
					r.GET(
						"/test",
						h.AuthMiddleware(),
						h.PermissionMiddleware(permission),
						func(c *gin.Context) { c.Status(http.StatusNoContent) },
					)
					req := httptest.NewRequest(http.MethodGet, "/test", nil)
					req.RemoteAddr = "127.0.0.1:1234"
					w := httptest.NewRecorder()
					r.ServeHTTP(w, req)
					allowed := tc.wantAudit
					if permission == "manage_views" {
						allowed = tc.wantViews
					}
					want := http.StatusForbidden
					if allowed {
						want = http.StatusNoContent
					}
					require.Equal(t, want, w.Code)
				})
			}
		})
	}
}

func TestWorkspaceCompatibilityDoesNotExpandTokens(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	h.identityRepo = identityTestRepository{}
	pg.On("GetAPITokenByHash", mock.Anything).Return(&models.APIToken{
		ID: 1, Username: "member", Permissions: "view_ips,manage_views,view_audit_logs",
	}, nil)
	pg.On("UpdateTokenLastUsed", 1, mock.Anything).Return(nil)
	pg.On("GetAdmin", "member").Return(&models.AdminAccount{
		Username: "member", AuthSource: "local", Permissions: "gui_read,view_ips",
	}, nil)
	r := gin.New()
	r.GET("/test", h.AuthMiddleware(), func(c *gin.Context) {
		require.Equal(t, "view_ips", c.GetString("permissions"))
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer synthetic-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
}
