package api

import (
	"bytes"
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
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Regression tests for the 2026-10 security audit findings.

func TestWebSocket_RejectsOversizedClientMessages(t *testing.T) {
	h, _, _, _, _ := setupTest()
	assert.False(t, h.upgrader.EnableCompression, "permessage-deflate must stay off: read limits count wire bytes")

	// Drain hub registrations without the Redis-backed fan-out loop.
	h.hub = NewHub(nil)
	go func() {
		for {
			select {
			case <-h.hub.register:
			case <-h.hub.unregister:
			case <-h.hub.stop:
				return
			}
		}
	}()
	defer close(h.hub.stop)
	engine := gin.New()
	engine.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-ws-session-key"))))
	engine.GET("/ws", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("logged_in", true)
		s.Set("username", "admin")
		h.WS(c)
	})
	srv := httptest.NewServer(engine)
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, make([]byte, wsMaxMessageBytes*4)))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	require.Error(t, err)
	assert.True(t, websocket.IsCloseError(err, websocket.CloseMessageTooBig), "server must close with 1009, got %v", err)
}

func TestAPIHandler_RawIPsServesCachedSnapshot(t *testing.T) {
	h, repo, _, _, _ := setupTest()
	repo.On("GetBlockedIPKeys").Return([]string{"192.0.2.1"}, nil).Once()

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/raw", nil)
		h.RawIPs(c)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "192.0.2.1", w.Body.String())
	}
	repo.AssertNumberOfCalls(t, "GetBlockedIPKeys", 1)
}

func createOnlyContext(body, permissions string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/add", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "moderator-user")
	c.Set("permissions", permissions)
	return c, w
}

func TestAPIHandler_AddWhitelistCreateOnlyCannotReplaceEntry(t *testing.T) {
	h, repo, _, _, ipService := setupTest()
	repo.On("GetWhitelistedIPs").Return(map[string]models.WhitelistEntry{"198.51.100.7": {Reason: "permanent"}}, nil)

	c, w := createOnlyContext(`{"ip":"198.51.100.7","reason":"x"}`, "whitelist_ips")
	h.AddWhitelist(c)
	assert.Equal(t, http.StatusConflict, w.Code)

	ipService.On("WhitelistIP", mock.Anything, "198.51.100.8", "x", "moderator-user", "").Return(nil).Once()
	c, w = createOnlyContext(`{"ip":"198.51.100.8","reason":"x"}`, "whitelist_ips")
	h.AddWhitelist(c)
	assert.Equal(t, http.StatusOK, w.Code, "creating a new entry stays allowed")

	ipService.On("WhitelistIP", mock.Anything, "198.51.100.7", "x", "moderator-user", "").Return(nil).Once()
	c, w = createOnlyContext(`{"ip":"198.51.100.7","reason":"x"}`, "manage_whitelist")
	h.AddWhitelist(c)
	assert.Equal(t, http.StatusOK, w.Code, "manage_whitelist may update entries")
	ipService.AssertExpectations(t)
}

func TestAPIHandler_AddWhitelistRejectsPastExpiry(t *testing.T) {
	h, _, _, _, ipService := setupTest()
	c, w := createOnlyContext(`{"ip":"198.51.100.7","reason":"x","expires_at":"2000-01-01T00:00:00Z"}`, "manage_whitelist")
	h.AddWhitelist(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	ipService.AssertNotCalled(t, "WhitelistIP", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAPIHandler_AddExcludedCreateOnlyCannotReplaceEntry(t *testing.T) {
	h, repo, _, _, ipService := setupTest()
	repo.On("GetExcludedEntries").Return(map[string]models.ExcludedEntry{"198.51.100.0/24": {Value: "198.51.100.0/24"}}, nil)

	c, w := createOnlyContext(`{"value":"198.51.100.9/24","reason":"x","confirm":true}`, "exclude_ips")
	h.AddExcluded(c)
	assert.Equal(t, http.StatusConflict, w.Code, "canonical form of an existing exclusion is refused")

	c, w = createOnlyContext(`{"value":"203.0.113.0/24","reason":"x","expires_at":"2000-01-01T00:00:00Z","confirm":true}`, "manage_excluded")
	h.AddExcluded(c)
	assert.Equal(t, http.StatusBadRequest, w.Code, "past expiry is refused")
	ipService.AssertNotCalled(t, "AddExcluded", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAPIHandler_WebhookSelfWhitelistKeepsExistingEntry(t *testing.T) {
	h, repo, _, _, _ := setupTest()
	repo.On("GetWhitelistedIPs").Return(map[string]models.WhitelistEntry{"198.51.100.7": {Reason: "permanent"}}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/webhook", nil)
	c.Set("permissions", "whitelist_ips")
	h.handleWebhookWhitelist(c, webhookRequest{IP: "198.51.100.7", Act: "selfwhitelist"}, "edge", "198.51.100.7", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertNotCalled(t, "WhitelistIP", mock.Anything, mock.Anything)
}

func TestAPIHandler_APITokenCannotManageTokens(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	for name, handler := range map[string]gin.HandlerFunc{
		"create": h.CreateAPIToken,
		"update": h.UpdateAPITokenPermissions,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			form := url.Values{"name": {"minted"}, "permissions": {"block_ips"}, "allowed_ips": {""}}
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/settings/tokens", strings.NewReader(form.Encode()))
			c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			c.Params = gin.Params{{Key: "id", Value: "1"}}
			c.Set("username", "member")
			c.Set("permissions", "manage_api_tokens,block_ips")
			c.Set("token_auth", true)
			handler(c)
			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
	pg.AssertNotCalled(t, "CreateAPIToken", mock.Anything)
	pg.AssertNotCalled(t, "UpdateAPITokenPermissions", mock.Anything, mock.Anything, mock.Anything)
}

func TestAPIHandler_LoginRejectsStaleEnrollmentProof(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Blocklist App", AccountName: "member"})
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		version  int
		issued   time.Time
		accepted bool
	}{
		{name: "current proof", version: 2, issued: time.Now(), accepted: true},
		{name: "password changed since proof", version: 1, issued: time.Now()},
		{name: "expired proof", version: 2, issued: time.Now().Add(-pendingEnrollmentTTL - time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pg := setupAuthTest()
			pg.On("GetAdmin", "member").Return(&models.AdminAccount{
				Username: "member", AuthSource: "local", SessionVersion: 2, Permissions: "gui_read",
			}, nil)
			pg.On("UpdateAdminToken", "member", key.Secret()).Return(nil).Maybe()
			pg.On("LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

			w := httptest.NewRecorder()
			_, r := setupHTMLTest(w)
			r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-enroll-session-key"))))
			r.POST("/login", func(c *gin.Context) {
				s := sessions.Default(c)
				s.Set("pending_auth_user", "member")
				s.Set("pending_auth_verified", true)
				s.Set("pending_totp_secret", key.Secret())
				s.Set("pending_auth_version", tc.version)
				s.Set("pending_auth_time", tc.issued.Unix())
				h.Login(c)
			})
			code, err := totp.GenerateCode(key.Secret(), time.Now())
			require.NoError(t, err)
			form := url.Values{"username": {"member"}, "setup_secret": {key.Secret()}, "totp": {code}}
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.ServeHTTP(w, req)

			if tc.accepted {
				pg.AssertCalled(t, "UpdateAdminToken", "member", key.Secret())
			} else {
				pg.AssertNotCalled(t, "UpdateAdminToken", mock.Anything, mock.Anything)
				assert.Contains(t, w.Body.String(), "Session expired or invalid setup attempt")
			}
		})
	}
}
