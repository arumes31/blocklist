package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type accountStatusRepository struct {
	IdentityRepositoryProvider
	change *models.AdminStatusChange
	err    error
}

func (r *accountStatusRepository) SetAdminDisabled(_ context.Context, change models.AdminStatusChange) error {
	r.change = &change
	return r.err
}

func TestChangeAdminStatus(t *testing.T) {
	for _, tc := range []struct {
		name, body, permissions string
		status                  int
		err                     error
	}{
		{name: "disable", body: `{"username":"member","disabled":true}`, status: 200},
		{name: "enable", body: `{"username":"member","disabled":false}`, status: 200},
		{name: "requires explicit status", body: `{"username":"member"}`, status: 400},
		{name: "rejects null", body: `{"username":"member","disabled":null}`, status: 400},
		{name: "rejects invalid boolean", body: `{"username":"member","disabled":"true"}`, status: 400},
		{name: "rejects blank name", body: `{"username":" ","disabled":true}`, status: 400},
		{name: "protects recovery", body: `{"username":"admin","disabled":true}`, status: 403},
		{name: "protects self", body: `{"username":"manager","disabled":true}`, status: 403},
		{name: "requires permission", body: `{"username":"member","disabled":true}`, permissions: "view_admins", status: 403},
		{name: "cannot manage stronger account", body: `{"username":"member","disabled":true}`, permissions: "manage_admins", status: 403},
		{name: "reports concurrent change", body: `{"username":"member","disabled":true}`, status: 409, err: repository.ErrIdentityConflict},
		{name: "reports denied change", body: `{"username":"member","disabled":true}`, status: 403, err: repository.ErrIdentityDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			repo := &accountStatusRepository{err: tc.err}
			h.identityRepo = repo
			account := &models.AdminAccount{Username: "member", Permissions: "gui_read,view_admins", SessionVersion: 7}
			pg.On("GetAdmin", "member").Return(account, nil).Maybe()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "manager")
			permissions := tc.permissions
			if permissions == "" {
				permissions = models.AllPermissions()
			}
			c.Set("permissions", permissions)
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/change_status", strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")
			h.ChangeAdminStatus(c)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.status == http.StatusOK {
				require.NotNil(t, repo.change)
				require.Equal(t, *account, repo.change.Expected)
				require.Equal(t, tc.name == "disable", repo.change.Disabled)
				require.Equal(t, "manager", repo.change.Actor)
				require.Equal(t, "admin", repo.change.RecoveryAdmin)
			} else if tc.err == nil {
				require.Nil(t, repo.change)
			}
		})
	}
}

func TestDisabledAccountRejectsEveryAuthenticationPath(t *testing.T) {
	for _, path := range []string{"bearer", "basic", "session", "session check", "enrollment", "final login"} {
		t.Run(path, func(t *testing.T) {
			h, _, pg, auth, _ := setupTest()
			h.identityRepo = identityTestRepository{}
			pg.On("GetAdmin", "member").Return(&models.AdminAccount{
				Username: "member", AuthSource: "local", Permissions: models.AllPermissions(), Disabled: true,
			}, nil)
			w := httptest.NewRecorder()
			_, r := setupHTMLTest(w)
			r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-status-session-key"))))
			r.Use(func(c *gin.Context) {
				s := sessions.Default(c)
				s.Set("username", "member")
				s.Set("client_ip", "127.0.0.1")
				s.Set("session_version", 0)
				if path == "session" || path == "session check" {
					s.Set("logged_in", true)
				}
				if path == "enrollment" {
					s.Set("pending_auth_user", "member")
					s.Set("pending_auth_verified", true)
					s.Set("pending_totp_secret", "JBSWY3DPEHPK3PXP")
				}
			})
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			status := http.StatusUnauthorized
			switch path {
			case "bearer":
				pg.On("GetAPITokenByHash", mock.Anything).Return(&models.APIToken{Username: "member"}, nil)
				req.Header.Set("Authorization", "Bearer synthetic-token")
			case "basic":
				req.URL.Path = "/api/v1/whitelists-raw"
				req.SetBasicAuth("member", "synthetic-password")
			case "session", "session check":
				status = http.StatusFound
			case "enrollment", "final login":
				form := url.Values{"username": {"member"}, "totp": {"123456"}}
				if path == "enrollment" {
					form.Set("setup_secret", "JBSWY3DPEHPK3PXP")
				} else {
					form.Set("password", "synthetic-password")
					auth.On("CheckAuth", "member", "synthetic-password", "123456").Return(true)
				}
				req = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if path == "enrollment" || path == "final login" {
				r.POST("/test", h.Login)
			} else {
				middleware := h.AuthMiddleware()
				if path == "session check" {
					middleware = h.SessionCheckMiddleware()
				}
				r.GET(req.URL.Path, middleware, func(c *gin.Context) { c.Status(http.StatusNoContent) })
			}
			r.ServeHTTP(w, req)
			require.Equal(t, status, w.Code, w.Body.String())
			pg.AssertNotCalled(t, "UpdateAdminToken", mock.Anything, mock.Anything)
			pg.AssertNotCalled(t, "UpdateTokenLastUsed", mock.Anything, mock.Anything)
		})
	}
}
