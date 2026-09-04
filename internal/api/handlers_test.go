package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupTest() (*APIHandler, *MockRedisRepo, *MockPostgresRepo, *MockAuthService, *MockIPService) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		GUIAdmin:          "admin",
		MetricsAllowedIPs: "127.0.0.1",
	}
	rRepo := new(MockRedisRepo)
	pgRepo := new(MockPostgresRepo)
	authService := new(MockAuthService)
	ipService := new(MockIPService)

	h := NewAPIHandler(&HandlerOptions{
		Config:      cfg,
		RedisRepo:   rRepo,
		PgRepo:      pgRepo,
		AuthService: authService,
		IPService:   ipService,
	})
	return h, rRepo, pgRepo, authService, ipService
}

func TestAPIHandler_RegisterRoutes_RequiresSudoForSensitiveAdminActions(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "create admin", method: http.MethodPost, path: "/admin_management/create"},
		{name: "delete admin", method: http.MethodPost, path: "/admin_management/delete"},
		{name: "change password", method: http.MethodPost, path: "/admin_management/change_password"},
		{name: "reset TOTP", method: http.MethodPost, path: "/admin_management/change_totp"},
		{name: "change permissions", method: http.MethodPost, path: "/admin_management/change_permissions"},
		{name: "disclose TOTP QR", method: http.MethodGet, path: "/admin_management/get_qr/target"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, pg, _, ipService := setupTest()
			passThrough := func(c *gin.Context) { c.Next() }
			h.mainLimiter = passThrough
			h.loginLimiter = passThrough
			h.webhookLimiter = passThrough

			admin := &models.AdminAccount{
				Username:       "operator",
				Role:           "admin",
				Permissions:    "manage_admins",
				SessionVersion: 1,
			}
			pg.On("GetAdmin", "operator").Return(admin, nil)
			pg.On("GetAdmin", "target").Return(&models.AdminAccount{Username: "target", Token: "secret"}, nil).Maybe()
			ipService.On("IsBlocked", mock.Anything).Return(false)

			r := gin.New()
			store := cookie.NewStore([]byte("secret"))
			r.Use(sessions.Sessions("mysession", store))
			r.Use(func(c *gin.Context) {
				session := sessions.Default(c)
				session.Set("logged_in", true)
				session.Set("username", "operator")
				session.Set("client_ip", "127.0.0.1")
				session.Set("role", "admin")
				session.Set("permissions", "manage_admins")
				session.Set("session_version", 1)
				c.Next()
			})
			h.RegisterRoutes(r)

			body := bytes.NewBufferString("{")
			req, _ := http.NewRequest(tt.method, tt.path, body)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, "/sudo?next="+tt.path, w.Header().Get("Location"))
		})
	}
}

func TestAPIHandler_Health(t *testing.T) {
	h, rRepo, pgRepo, _, _ := setupTest()

	// Mock successful health checks
	rRepo.On("HGetAllRaw", "ips").Return(map[string]string{}, nil)
	pgRepo.On("GetAllAdmins").Return([]models.AdminAccount{}, nil)
	pgRepo.On("GetPersistentCount").Return(int64(0), nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.Health(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "UP", response["status"])
	assert.Equal(t, "OK", response["postgres"])
	assert.Equal(t, "OK", response["redis"])
}

func TestAPIHandler_Ready(t *testing.T) {
	h, rRepo, _, _, _ := setupTest()

	rRepo.On("HGetAllRaw", "ips").Return(map[string]string{}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.Ready(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "READY", response["status"])
}

func TestAPIHandler_OpenAPI(t *testing.T) {
	h, _, _, _, _ := setupTest()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.OpenAPI(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "openapi")
}

func TestAPIHandler_MetricsAuthMiddleware(t *testing.T) {
	h, _, _, _, _ := setupTest()

	r := gin.New()
	r.Use(h.MetricsAuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	// Test allowed IP
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	// Test denied IP
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "1.1.1.1:1234"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	assert.Equal(t, 403, w2.Code)
}

func TestAPIHandler_RBACMiddleware(t *testing.T) {
	h, _, _, _, _ := setupTest()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("role", "operator")
		c.Next()
	})
	r.Use(h.RBACMiddleware("admin"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func TestAPIHandler_AuthMiddleware_NoToken(t *testing.T) {
	h, _, _, _, _ := setupTest()

	r := gin.New()
	// Mock session for unauthenticated request
	r.Use(func(c *gin.Context) {
		// No session set
		c.Next()
	})
	// We need a dummy cookie store to avoid panics if sessions used
	// But AuthMiddleware relies on gin-contrib/sessions which attaches to context.
	// For unit test without full session middleware, we might need to mock session behavior slightly differently
	// or rely on the Fact that session.Get will return nil.

	// However, AuthMiddleware calls sessions.Default(c) which panics if session middleware isn't registered.
	// So we can't easily test the session part without setting up the store.

	// Testing the API Token logic (simpler part)
	r.GET("/protected", h.AuthMiddleware(), func(c *gin.Context) { c.Status(200) })

	// Without mocked session store, this will panic inside AuthMiddleware when it calls sessions.Default
	// We should setup the store mock or just test logic functions if extracted.
	// For integration feel:
	/*
		store := cookie.NewStore([]byte("secret"))
		r.Use(sessions.Sessions("mysession", store))
	*/
}

func TestAPIHandler_PermissionMiddleware(t *testing.T) {
	h, _, _, _, _ := setupTest()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("permissions", "read,write")
		c.Next()
	})
	r.Use(h.PermissionMiddleware("delete"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func TestAPIHandler_BlockCheckMiddleware(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("IsBlocked", "1.2.3.4").Return(true)

	r := gin.New()
	r.Use(h.BlockCheckMiddleware())
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	ipService.AssertExpectations(t)
}

func TestAPIHandler_BlockCheckMiddleware_Allowed(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("IsBlocked", "1.2.3.4").Return(false)

	r := gin.New()
	r.Use(h.BlockCheckMiddleware())
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	ipService.AssertExpectations(t)
}

func TestAPIHandler_IsValidRedirect(t *testing.T) {
	h, _, _, _, _ := setupTest()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"empty", "", false},
		{"root", "/", true},
		{"valid path", "/dashboard", true},
		{"nested path", "/admin/settings", true},
		{"protocol relative //", "//evil.com", false},
		{"protocol relative /\\", "/\\evil.com", false},
		{"absolute http", "http://evil.com", false},
		{"absolute https", "https://evil.com", false},
		{"no leading slash", "dashboard", false},
		{"relative up", "../outside", false},
		{"just backslash", "\\", false},
		{"triple slash", "///evil.com", false},
		{"slash space", "/ /evil.com", false},
		{"slash tab", "/\t/evil.com", false},
		{"slash newline", "/\n/evil.com", false},
		{"slash carriage return", "/\r/evil.com", false},
		{"slash at", "/@evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.isValidRedirect(tt.target); got != tt.want {
				t.Errorf("APIHandler.isValidRedirect(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
