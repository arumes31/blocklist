package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
	gorillasessions "github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func postJSON(h gin.HandlerFunc, username, permissions, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", username)
	c.Set("permissions", permissions)
	h(c)
	return w
}

// whitelist_ips must not be able to exempt the entire address space, and no
// caller may store a zero-length prefix.
func TestAPIHandler_AddWhitelistRejectsBroadPrefixes(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	for _, tc := range []struct {
		perms string
		ip    string
	}{
		{"gui_read,whitelist_ips", "::/0"},
		{"gui_read,whitelist_ips", "0.0.0.0/0"},
		{"gui_read,whitelist_ips", "10.0.0.0/8"},
		{"gui_read,manage_whitelist", "0.0.0.0/0"},
		{"gui_read,manage_whitelist", "::/0"},
	} {
		w := postJSON(h.AddWhitelist, "moderator", tc.perms, `{"ip":"`+tc.ip+`","note":"maintenance"}`)
		assert.Equal(t, http.StatusBadRequest, w.Code, "%s %s", tc.perms, tc.ip)
		assert.Contains(t, w.Body.String(), "Prefix too broad")
	}
	ipService.AssertNotCalled(t, "WhitelistIP", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	ipService.AssertNotCalled(t, "WhitelistIPIfAbsent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	ipService.On("WhitelistIPIfAbsent", mock.Anything, "10.1.0.0/16", "office", "moderator", "").Return(true, nil).Once()
	w := postJSON(h.AddWhitelist, "moderator", "gui_read,whitelist_ips", `{"ip":"10.1.0.0/16","note":"office"}`)
	assert.Equal(t, http.StatusOK, w.Code)

	ipService.On("WhitelistIP", mock.Anything, "10.0.0.0/8", "lab", "editor", "").Return(nil).Once()
	w = postJSON(h.AddWhitelist, "editor", "gui_read,manage_whitelist", `{"ip":"10.0.0.0/8","note":"lab"}`)
	assert.Equal(t, http.StatusOK, w.Code)
	ipService.AssertExpectations(t)
}

func TestAPIHandler_AddExcludedRejectsBroadPrefixes(t *testing.T) {
	h, _, _, _, ipService := setupTest()
	for _, perms := range []string{"gui_read,exclude_ips", "gui_read,manage_excluded"} {
		w := postJSON(h.AddExcluded, "moderator", perms, `{"value":"0.0.0.0/0","reason":"maintenance","confirm":true}`)
		assert.Equal(t, http.StatusBadRequest, w.Code, perms)
	}
	w := postJSON(h.AddExcluded, "moderator", "gui_read,exclude_ips", `{"value":"10.0.0.0/8","reason":"maintenance","confirm":true}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	ipService.AssertNotCalled(t, "AddExcluded", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	ipService.AssertNotCalled(t, "AddExcludedIfAbsent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// A NUL in the reason would make the audit insert fail while the policy
// change still lands, so it must be refused up front.
func TestAPIHandler_PolicyWritesRejectUnrecordableReason(t *testing.T) {
	h, _, _, _, ipService := setupTest()
	w := postJSON(h.AddWhitelist, "moderator", "gui_read,whitelist_ips", `{"ip":"192.0.2.5","note":"bad\u0000note"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	w = postJSON(h.AddExcluded, "moderator", "gui_read,exclude_ips", `{"value":"192.0.2.6","reason":"bad\u0000reason","confirm":true}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	ipService.AssertNotCalled(t, "WhitelistIPIfAbsent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	ipService.AssertNotCalled(t, "AddExcludedIfAbsent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	data := webhookRequest{IP: "192.0.2.7", Act: "whitelist", Reason: "bad\x00reason"}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/webhook", nil)
	assert.False(t, h.validateAndAuthorizeWebhook(c, "moderator", &data, "198.51.100.1"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// manage_api_tokens alone opens /settings but must not reveal outbound
// webhook URLs, which often embed credentials.
func TestAPIHandler_SettingsHidesWebhooksWithoutWebhookPermission(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()
	pgRepo.On("GetAPITokens", "tokenadmin").Return([]models.APIToken{}, nil)
	pgRepo.On("GetActiveWebhooks").Return([]models.OutboundWebhook{{ID: 1, URL: "https://hooks.example.test/secret-path", Events: "block", Active: true}}, nil)

	render := func(perms string) string {
		w := httptest.NewRecorder()
		c, _ := setupHTMLTest(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/settings", nil)
		c.Set("username", "tokenadmin")
		c.Set("permissions", perms)
		h.Settings(c)
		require.Equal(t, http.StatusOK, w.Code)
		return w.Body.String()
	}

	body := render("gui_read,manage_api_tokens")
	assert.NotContains(t, body, "secret-path")
	assert.NotContains(t, body, "Outbound Webhooks")
	pgRepo.AssertNotCalled(t, "GetActiveWebhooks")

	assert.Contains(t, render("gui_read,view_settings"), "secret-path")
	assert.Contains(t, render("gui_read,manage_webhooks"), "secret-path")
}

// A WebSocket must close once its session has been idle past
// SESSION_IDLE_MINUTES, matching the HTTP path.
func TestWSSessionCurrentEnforcesIdleTimeout(t *testing.T) {
	h, _, _, _, _ := setupTest()
	h.cfg.SessionIdleMinutes = 30
	store := gorillasessions.NewCookieStore([]byte("synthetic-ws-session-key-32-bytes!"))
	h.sessionStore = store
	loginTime := time.Now().UTC().Format(time.RFC3339)

	requestWith := func(lastSeen int64) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		s, err := store.New(req, SessionCookieName)
		require.NoError(t, err)
		s.Values = map[interface{}]interface{}{
			"logged_in": true, "username": "admin", "session_version": 1,
			"login_time": loginTime, "last_seen": lastSeen,
		}
		w := httptest.NewRecorder()
		require.NoError(t, s.Save(req, w))
		ws := httptest.NewRequest(http.MethodGet, "/ws", nil)
		ws.AddCookie(w.Result().Cookies()[0])
		return ws
	}

	assert.True(t, h.wsSessionCurrent(requestWith(time.Now().Add(-5*time.Minute).Unix()), "admin", 1, loginTime))
	assert.False(t, h.wsSessionCurrent(requestWith(time.Now().Add(-31*time.Minute).Unix()), "admin", 1, loginTime))

	h.cfg.SessionIdleMinutes = 0
	assert.True(t, h.wsSessionCurrent(requestWith(time.Now().Add(-31*time.Minute).Unix()), "admin", 1, loginTime), "idle expiry disabled")
}
