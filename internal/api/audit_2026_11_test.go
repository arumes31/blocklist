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
	gorillasessions "github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A dashboard viewer without view_stats must not receive aggregate statistics.
func TestAPIHandler_DashboardWithholdsStatsWithoutViewStats(t *testing.T) {
	h, _, pgRepo, _, ipService := setupTest()
	pgRepo.On("GetSavedViews", "viewer").Return([]models.SavedView{}, nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	c.Set("username", "viewer")
	c.Set("permissions", "gui_read,view_ips")
	h.Dashboard(c)

	require.Equal(t, http.StatusOK, w.Code)
	ipService.AssertNotCalled(t, "Stats", mock.Anything)
	ipService.AssertNotCalled(t, "GetExcludedCount", mock.Anything)
	assert.Regexp(t, `const statsAllowed = \s*false\s* === true;`, w.Body.String())
	assert.NotContains(t, w.Body.String(), "nav-event-logs", "event logs need view_event_logs")
}

// The two-step login must reject a saved password proof issued for an older
// credential version or too long ago, without checking the TOTP code.
func TestAPIHandler_StagedLoginRejectsStaleFirstFactor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  any
		issued   time.Time
		accepted bool
	}{
		{name: "current proof", version: 4, issued: time.Now(), accepted: true},
		{name: "password changed since proof", version: 3, issued: time.Now()},
		{name: "expired proof", version: 4, issued: time.Now().Add(-pendingEnrollmentTTL - time.Minute)},
		{name: "proof without version", version: nil, issued: time.Now()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, auth, pg := setupAuthTest()
			pg.On("GetAdmin", "member").Return(&models.AdminAccount{
				Username: "member", AuthSource: "local", SessionVersion: 4, Permissions: "gui_read", Token: "SECRET",
			}, nil)
			pg.On("LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
			auth.On("VerifyTOTP", "member", "123456").Return(true).Maybe()

			w := httptest.NewRecorder()
			_, r := setupHTMLTest(w)
			r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-staged-session-key"))))
			r.POST("/login", func(c *gin.Context) {
				s := sessions.Default(c)
				s.Set("pending_auth_user", "member")
				s.Set("pending_auth_verified", true)
				if tc.version != nil {
					s.Set("pending_auth_version", tc.version)
				}
				s.Set("pending_auth_time", tc.issued.Unix())
				h.Login(c)
			})
			form := url.Values{"username": {"member"}, "totp": {"123456"}}
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.ServeHTTP(w, req)

			if tc.accepted {
				auth.AssertCalled(t, "VerifyTOTP", "member", "123456")
				assert.Equal(t, http.StatusFound, w.Code)
			} else {
				auth.AssertNotCalled(t, "VerifyTOTP", mock.Anything, mock.Anything)
				assert.Contains(t, w.Body.String(), "Session expired or invalid login attempt")
			}
		})
	}
}

func TestFeedAddressesDropsMalformedKeys(t *testing.T) {
	got := feedAddresses([]string{
		"192.0.2.1",
		"fe80::1%eth0\n198.51.100.1",
		"not-an-ip",
		"2001:DB8::1",
		"2001:db8::1",
	})
	assert.Equal(t, []string{"192.0.2.1", "2001:db8::1"}, got)
}

func TestAPIHandler_GetIPDetailsRejectsNonAddressTargets(t *testing.T) {
	h, _, _, _, ipService := setupTest()
	ipService.On("GetIPDetails", mock.Anything, "admin").Return(map[string]interface{}(nil), assert.AnError)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ips/admin/details", nil)
	c.Params = gin.Params{{Key: "ip", Value: "admin"}}
	h.GetIPDetails(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// overrideRoleRepository records role assignments for the override tests.
type overrideRoleRepository struct {
	IdentityRepositoryProvider
	assigned *models.RoleAssignment
}

func (r *overrideRoleRepository) GetRole(_ context.Context, id string) (*models.AccessRole, error) {
	return &models.AccessRole{ID: id, Permissions: "gui_read", Revision: 7}, nil
}

func (r *overrideRoleRepository) AssignManagedAdminRole(_ context.Context, assignment models.RoleAssignment) error {
	r.assigned = &assignment
	return nil
}

// Clearing an Entra role override lets the next sign-in apply an unchecked
// directory role, so a delegated manager must not be able to do it.
func TestAPIHandler_ChangeAdminRoleOverrideRemovalNeedsFullAuthority(t *testing.T) {
	roleID := "viewer"
	target := &models.AdminAccount{
		Username: "entra-user", AuthSource: "entra", EntraRoleOverride: true,
		RoleID: &roleID, Role: roleID, Permissions: "gui_read",
	}
	for _, tc := range []struct {
		name        string
		permissions string
		override    bool
		status      int
	}{
		{name: "delegated manager keeps override", permissions: "gui_read,manage_admins", override: true, status: http.StatusOK},
		{name: "delegated manager clears override", permissions: "gui_read,manage_admins", override: false, status: http.StatusForbidden},
		{name: "full administrator clears override", permissions: models.AllPermissions(), override: false, status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			repo := &overrideRoleRepository{}
			h.identityRepo = repo
			pg.On("GetAdmin", "entra-user").Return(target, nil)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			body := `{"username":"entra-user","role":"viewer","entra_role_override":` + map[bool]string{true: "true", false: "false"}[tc.override] + `}`
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/change_role", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set("username", "manager")
			c.Set("permissions", tc.permissions)
			h.ChangeAdminRole(c)

			require.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.status == http.StatusOK {
				require.NotNil(t, repo.assigned)
				assert.Equal(t, 7, repo.assigned.RoleRevision, "the authorized role revision is passed on")
				assert.Equal(t, *target, repo.assigned.Expected, "the authorized target snapshot is passed on")
			} else {
				assert.Nil(t, repo.assigned)
			}
		})
	}
}

func TestMetricMethodIsBounded(t *testing.T) {
	assert.Equal(t, "GET", metricMethod("GET"))
	assert.Equal(t, "OTHER", metricMethod("PROPFIND"))
	assert.Equal(t, "OTHER", metricMethod("X-RANDOM-1234"))
}

// A WebSocket must close once the session that opened it has signed out or
// passed its absolute lifetime.
func TestWSSessionCurrentChecksLifetime(t *testing.T) {
	h, _, _, _, _ := setupTest()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	recent := time.Now().UTC().Format(time.RFC3339)
	old := time.Now().Add(-SessionMaxAge - time.Hour).UTC().Format(time.RFC3339)
	assert.True(t, h.wsSessionCurrent(req, "admin", 1, recent))
	assert.False(t, h.wsSessionCurrent(req, "admin", 1, old))
	assert.False(t, h.wsSessionCurrent(req, "admin", 1, "not-a-time"))
}

func TestWSSessionCurrentRereadsServerSession(t *testing.T) {
	h, _, _, _, _ := setupTest()
	store := gorillasessions.NewCookieStore([]byte("synthetic-ws-session-key-32-bytes!"))
	h.sessionStore = store
	loginTime := time.Now().UTC().Format(time.RFC3339)

	cookieFor := func(values map[interface{}]interface{}) *http.Cookie {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		s, err := store.New(req, wsSessionName)
		require.NoError(t, err)
		s.Values = values
		w := httptest.NewRecorder()
		require.NoError(t, s.Save(req, w))
		return w.Result().Cookies()[0]
	}
	signedIn := map[interface{}]interface{}{
		"logged_in": true, "username": "admin", "session_version": 3, "login_time": loginTime,
	}

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.AddCookie(cookieFor(signedIn))
	assert.True(t, h.wsSessionCurrent(req, "admin", 3, loginTime))
	assert.False(t, h.wsSessionCurrent(req, "admin", 4, loginTime), "credential version changed")

	loggedOut := httptest.NewRequest(http.MethodGet, "/ws", nil)
	loggedOut.AddCookie(cookieFor(map[interface{}]interface{}{}))
	assert.False(t, h.wsSessionCurrent(loggedOut, "admin", 3, loginTime), "signed-out session")

	noCookie := httptest.NewRequest(http.MethodGet, "/ws", nil)
	assert.False(t, h.wsSessionCurrent(noCookie, "admin", 3, loginTime))
}
