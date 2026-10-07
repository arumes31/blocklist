package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/service"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type entraFlowStub struct {
	result *service.EntraResult
	err    error
}

func (*entraFlowStub) Start(context.Context, string, string) (string, string, error) {
	return "", "", errors.New("unexpected authorization start")
}

func (s *entraFlowStub) Finish(context.Context, string, string, string) (*service.EntraResult, error) {
	return s.result, s.err
}

type entraCallbackRepository struct {
	IdentityRepositoryProvider
	account *models.AdminAccount
	calls   int
}

func (r *entraCallbackRepository) SignInEntra(context.Context, models.EntraIdentity, bool) (*models.AdminAccount, error) {
	r.calls++
	return r.account, nil
}

func TestEntraReauthenticationCallback(t *testing.T) {
	for _, tc := range []struct {
		name, message, reason string
		failure               error
		normal, wrongIdentity bool
		disabled, fresh       bool
		status, signIns       int
	}{
		{name: "fresh proof allows sensitive actions", fresh: true, status: 302, signIns: 1},
		{name: "ordinary SSO does not grant sudo", normal: true, status: 302, signIns: 1},
		{
			name: "missing auth time gives actionable configuration error", failure: service.ErrEntraAuthTimeMissing,
			status: 401, message: "auth_time optional claim", reason: "Reauthentication denied: auth_time_missing; configure the ID token optional claim",
		},
		{
			name: "old proof gives retry guidance", failure: service.ErrEntraAuthTimeStale,
			status: 401, message: "fresh sign-in", reason: "Reauthentication denied: auth_time_not_fresh",
		},
		{
			name: "another Microsoft account cannot verify the actor", fresh: true, wrongIdentity: true,
			status: 401, reason: "Sign-in could not be verified", message: "Microsoft sign-in could not be verified",
		},
		{
			name: "disabled account cannot regain access", fresh: true, disabled: true,
			status: 401, reason: "Sign-in could not be verified", message: "Microsoft sign-in could not be verified",
		},
		{
			name: "provider secrets never reach response or audit", failure: errors.New("private-token-provider-body"),
			status: 401, reason: "Sign-in could not be verified", message: "Microsoft sign-in could not be verified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			tenant, object := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
			account := &models.AdminAccount{
				Username: "bound-editor", AuthSource: "entra", Permissions: models.AllPermissions(), Role: "editor",
				EntraTenantID: &tenant, EntraObjectID: &object, Disabled: tc.disabled,
			}
			repo := &entraCallbackRepository{account: account}
			h.identityRepo = repo
			result := &service.EntraResult{
				Identity: models.EntraIdentity{TenantID: tenant, ObjectID: object, RoleID: "editor"},
				Username: account.Username, Next: "/admin_management", HasFreshAuth: tc.fresh,
			}
			if tc.normal {
				result.Username = ""
			}
			if tc.wrongIdentity {
				result.Identity.ObjectID = "33333333-3333-3333-3333-333333333333"
			}
			h.entraService = &entraFlowStub{result: result, err: tc.failure}
			if tc.failure == nil && !tc.normal {
				pg.On("GetAdmin", account.Username).Return(account, nil).Once()
			}
			if tc.reason != "" {
				pg.On("LogAction", "system", "ENTRA_LOGIN_FAILURE", "REDACTED", tc.reason).Return(nil).Once()
			}
			w := httptest.NewRecorder()
			_, router := setupHTMLTest(w)
			router.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-entra-test-session-key"))))
			router.GET("/seed", func(c *gin.Context) {
				s := sessions.Default(c)
				s.Set("username", account.Username)
				s.Set("logged_in", true)
				s.Set("auth_source", "entra")
				s.Set("sudo_time", time.Now().Add(-6*time.Minute).Unix())
				require.NoError(t, s.Save())
			})
			router.GET("/auth/entra/callback", h.EntraCallback)
			router.POST("/sensitive", h.SudoMiddleware(), func(c *gin.Context) {
				require.Equal(t, account.Username, sessions.Default(c).Get("username"))
				c.Status(http.StatusNoContent)
			})
			seed := httptest.NewRecorder()
			router.ServeHTTP(seed, httptest.NewRequest(http.MethodGet, "/seed", nil))
			sessionCookie := seed.Result().Cookies()[0]
			req := httptest.NewRequest(http.MethodGet, "/auth/entra/callback?state=synthetic&code=synthetic", nil)
			req.AddCookie(sessionCookie)
			req.AddCookie(&http.Cookie{Name: entraFlowCookie, Value: strings.Repeat("x", 43)})
			router.ServeHTTP(w, req)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			require.Equal(t, tc.signIns, repo.calls)
			if tc.status == http.StatusFound {
				require.Equal(t, "/admin_management", w.Header().Get("Location"))
			}
			require.Contains(t, w.Body.String(), tc.message)
			require.NotContains(t, w.Body.String(), "private-token-provider-body")
			if errors.Is(tc.failure, service.ErrEntraAuthTimeMissing) || errors.Is(tc.failure, service.ErrEntraAuthTimeStale) {
				require.Contains(t, w.Body.String(), "/auth/entra/login?reauth=1")
				require.Contains(t, w.Body.String(), "Verify with Microsoft")
				require.NotContains(t, w.Body.String(), "Continue with Microsoft")
			}
			for _, candidate := range w.Result().Cookies() {
				if candidate.Name == "session" {
					sessionCookie = candidate
				}
			}
			check := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
			check.Header.Set("Accept", "application/json")
			check.AddCookie(sessionCookie)
			checked := httptest.NewRecorder()
			router.ServeHTTP(checked, check)
			want := http.StatusForbidden
			if tc.fresh && tc.status == http.StatusFound {
				want = http.StatusNoContent
			}
			require.Equal(t, want, checked.Code)
			pg.AssertExpectations(t)
		})
	}
}

func TestDisabledEntraServiceStaysNil(t *testing.T) {
	h, _, _, _, _ := setupTest()
	require.Nil(t, h.entraService)
}
