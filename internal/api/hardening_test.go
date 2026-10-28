package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func sessionRouter(h *APIHandler, seed func(sessions.Session), handlers ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-hardening-session-key"))))
	r.Use(func(c *gin.Context) {
		seed(sessions.Default(c))
		c.Next()
	})
	r.Any("/test", handlers...)
	return r
}

func TestAuthMiddlewareInvalidBearerDoesNotFallBackToSession(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	pg.On("GetAPITokenByHash", mock.Anything).Return(nil, sql.ErrNoRows)
	r := sessionRouter(h, func(s sessions.Session) {
		s.Set("logged_in", true)
		s.Set("username", "admin")
		s.Set("client_ip", "192.0.2.1")
	}, h.AuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Authorization", "Bearer forged")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	pg.AssertNotCalled(t, "GetAdmin", mock.Anything)
}

func TestAuthMiddlewareExpiresIdleSessions(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	h.cfg.SessionIdleMinutes = 10
	pg.On("GetAdmin", "member").Return(&models.AdminAccount{Username: "member", Permissions: "gui_read"}, nil).Maybe()

	for name, lastSeen := range map[string]time.Time{"idle": time.Now().Add(-11 * time.Minute), "active": time.Now().Add(-2 * time.Minute)} {
		t.Run(name, func(t *testing.T) {
			r := sessionRouter(h, func(s sessions.Session) {
				s.Set("logged_in", true)
				s.Set("username", "member")
				s.Set("client_ip", "192.0.2.1")
				s.Set("last_seen", lastSeen.Unix())
			}, h.AuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if name == "idle" {
				assert.Equal(t, http.StatusFound, w.Code)
				assert.Equal(t, "/login", w.Header().Get("Location"))
			} else {
				assert.Equal(t, http.StatusNoContent, w.Code)
			}
		})
	}
}

func TestAuthMiddlewareEnforcesAbsoluteSessionLifetime(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	h.cfg.SessionIdleMinutes = 10
	pg.On("GetAdmin", "member").Return(&models.AdminAccount{Username: "member", Permissions: "gui_read"}, nil).Maybe()
	r := sessionRouter(h, func(s sessions.Session) {
		s.Set("logged_in", true)
		s.Set("username", "member")
		s.Set("client_ip", "192.0.2.1")
		s.Set("last_seen", time.Now().Unix()) // active, so only the absolute limit applies
		s.Set("login_time", time.Now().Add(-SessionMaxAge-time.Hour).UTC().Format(time.RFC3339))
	}, h.AuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestLogoutIgnoresCrossSiteNavigation(t *testing.T) {
	h, _, _, _, _ := setupTest()
	r := sessionRouter(h, func(s sessions.Session) { s.Set("logged_in", true) }, h.Logout)

	for site, location := range map[string]string{"cross-site": "/dashboard", "same-origin": "/login", "": "/login"} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, location, w.Header().Get("Location"), "Sec-Fetch-Site %q", site)
	}
}

func TestVerifySudoRejectsTokenAndSessionlessCallers(t *testing.T) {
	h, _, _, _, _ := setupTest()
	r := sessionRouter(h, func(sessions.Session) {}, func(c *gin.Context) {
		c.Set("token_auth", true)
		h.VerifySudo(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/test", nil))
	assert.Equal(t, http.StatusForbidden, w.Code, "must not panic or elevate")
}
