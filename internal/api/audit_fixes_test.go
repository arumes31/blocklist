package api

import (
	"math"
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
	"golang.org/x/crypto/bcrypt"
)

func basicAuthRouter(h *APIHandler) *gin.Engine {
	r := gin.New()
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-basic-session-key"))))
	r.GET("/api/v1/whitelists-raw", h.BasicAuthLimiter(), h.AuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func TestBasicAuthDisabledByDefault(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whitelists-raw", nil)
	req.SetBasicAuth("member", "synthetic-password")
	basicAuthRouter(h).ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	pg.AssertNotCalled(t, "GetAdmin", "member")
}

func TestBasicAuthOptInIsRateLimitedBeforeBcrypt(t *testing.T) {
	h, _, pg, _, _ := setupTest()
	h.cfg.AllowBasicAuth = true
	limited := false
	h.loginLimiter = func(c *gin.Context) {
		if limited {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-password"), bcrypt.MinCost)
	require.NoError(t, err)
	pg.On("GetAdmin", "member").Return(&models.AdminAccount{
		Username: "member", AuthSource: "local", PasswordHash: string(hash), Permissions: "view_ips",
	}, nil)
	r := basicAuthRouter(h)

	for _, tc := range []struct {
		password string
		limited  bool
		status   int
	}{
		{password: "synthetic-password", status: http.StatusNoContent},
		{password: "wrong", status: http.StatusUnauthorized},
		{password: "synthetic-password", limited: true, status: http.StatusTooManyRequests},
	} {
		limited = tc.limited
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/whitelists-raw", nil)
		req.SetBasicAuth("member", tc.password)
		r.ServeHTTP(w, req)
		require.Equal(t, tc.status, w.Code, tc.password)
	}
	pg.AssertNumberOfCalls(t, "GetAdmin", 2)
}

func TestLoginRotatesPreLoginSession(t *testing.T) {
	h, auth, pg := setupAuthTest()
	pg.On("GetAdmin", "admin").Return(&models.AdminAccount{Username: "admin", Role: "admin", Token: "secret"}, nil)
	pg.On("LogAction", "admin", "LOGIN_SUCCESS", mock.Anything, "").Return(nil)
	auth.On("CheckAuth", "admin", "password", "123456").Return(true)

	r := gin.New()
	r.Use(sessions.Sessions("mysession", cookie.NewStore([]byte("synthetic-rotation-key"))))
	r.GET("/plant", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("planted", "attacker")
		_ = s.Save()
	})
	r.POST("/login", h.Login)
	r.GET("/read", func(c *gin.Context) {
		s := sessions.Default(c)
		c.JSON(http.StatusOK, gin.H{"planted": s.Get("planted"), "logged_in": s.Get("logged_in")})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/plant", nil))
	planted := w.Result().Cookies()
	require.NotEmpty(t, planted)

	form := url.Values{"username": {"admin"}, "password": {"password"}, "totp": {"123456"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(planted[len(planted)-1])
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusFound, w.Code)
	issued := w.Result().Cookies()
	require.GreaterOrEqual(t, len(issued), 2, "old session expired and a new one issued")
	require.Negative(t, issued[0].MaxAge)

	req = httptest.NewRequest(http.MethodGet, "/read", nil)
	req.AddCookie(issued[len(issued)-1])
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.JSONEq(t, `{"planted":null,"logged_in":true}`, w.Body.String())
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")",
		"+1":                "'+1",
		"-cmd":              "'-cmd",
		"@SUM(A1)":          "'@SUM(A1)",
		"\tx":               "'\tx",
		"\rx":               "'\rx",
		"Brute Force":       "Brute Force",
		"2001:db8::1":       "2001:db8::1",
		"":                  "",
	} {
		require.Equal(t, want, csvSafe(in), in)
	}
}

func TestBoundedTTL(t *testing.T) {
	require.Equal(t, time.Duration(0), boundedTTL(0, time.Second))
	require.Equal(t, time.Duration(0), boundedTTL(-5, time.Minute))
	require.Equal(t, 90*time.Second, boundedTTL(90, time.Second))
	require.Equal(t, maxBlockTTL, boundedTTL(math.MaxInt, time.Second))
	require.Equal(t, maxBlockTTL, boundedTTL(math.MaxInt, time.Minute))
}

func TestWebhookRejectsOversizedBodyAndReason(t *testing.T) {
	h, _, _, _, _ := setupTest()
	r := gin.New()
	r.POST("/webhook", func(c *gin.Context) { c.Set("username", "admin"); c.Next() }, h.Webhook)

	for name, body := range map[string]string{
		"oversized body": `{"ip":"203.0.113.1","act":"ban","reason":"` + strings.Repeat("a", maxAPIBodyBytes) + `"}`,
		"long reason":    `{"ip":"203.0.113.1","act":"ban","reason":"` + strings.Repeat("a", maxReasonLength+1) + `"}`,
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code, name)
	}
}
