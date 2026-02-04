package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/config"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func TestSecurity_IsValidRedirect(t *testing.T) {
	h := &APIHandler{}

	tests := []struct {
		target   string
		expected bool
	}{
		{"/dashboard", true},
		{"/settings?tab=webhooks", true},
		{"http://evil.com", false},
		{"https://evil.com/login", false},
		{"//evil.com", false}, // Protocol-relative
		{"/\\evil.com", false}, // Backslash trick
		{"", false},
		{"dashboard", false}, // Must start with /
	}

	for _, tt := range tests {
		result := h.isValidRedirect(tt.target)
		if result != tt.expected {
			t.Errorf("isValidRedirect(%q) = %v; want %v", tt.target, result, tt.expected)
		}
	}
}

func TestSecurity_AuthMiddleware_TestToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{GUIAdmin: "admin"}
	h := NewAPIHandler(cfg, nil, nil, nil, nil, nil, nil)

	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("test_session", store))
	r.Use(h.AuthMiddleware())
	r.GET("/test", func(c *gin.Context) {
		username, _ := c.Get("username")
		c.String(200, username.(string))
	})

	// 1. Valid test-token (should succeed in TestMode with no DB)
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for test-token, got %d", w.Code)
	}
	if w.Body.String() != "admin" {
		t.Errorf("Expected username 'admin', got %q", w.Body.String())
	}

	// 2. Invalid token
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("Authorization", "Bearer malicious-token")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code == http.StatusOK {
		t.Errorf("Expected failure for invalid token, got 200")
	}
}

func TestSecurity_PermissionMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{GUIAdmin: "admin"}
	h := NewAPIHandler(cfg, nil, nil, nil, nil, nil, nil)

	r := gin.New()
	// Mock authentication by setting context variables manually
	r.Use(func(c *gin.Context) {
		token := c.GetHeader("X-Test-Token")
		if token == "operator" {
			c.Set("username", "op_user")
			c.Set("permissions", "view_ips,block_ips")
		} else if token == "admin" {
			c.Set("username", "admin") // Superuser
			c.Set("permissions", "everything")
		} else {
			c.Set("username", "viewer")
			c.Set("permissions", "view_ips")
		}
		c.Next()
	})

	r.GET("/protected", h.PermissionMiddleware("block_ips"), func(c *gin.Context) {
		c.Status(200)
	})

	// 1. User HAS permission
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("X-Test-Token", "operator")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("Expected 200 for user with permission, got %d", w.Code)
	}

	// 2. User LACKS permission
	req2, _ := http.NewRequest("GET", "/protected", nil)
	req2.Header.Set("X-Test-Token", "viewer")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 403 {
		t.Errorf("Expected 403 for user without permission, got %d", w2.Code)
	}

	// 3. Superuser bypass (even if "block_ips" isn't explicitly in string)
	req3, _ := http.NewRequest("GET", "/protected", nil)
	req3.Header.Set("X-Test-Token", "admin")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != 200 {
		t.Errorf("Expected 200 for superuser bypass, got %d", w3.Code)
	}
}
