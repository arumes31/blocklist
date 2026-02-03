package api

import (
	"blocklist/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAPIHandler_PermissionMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAPIHandler(&config.Config{}, nil, nil, nil, nil, nil, nil)

	tests := []struct {
		name          string
		userPerms     string
		requiredPerms []string
		expectedCode  int
	}{
		{
			name:          "No permissions required",
			userPerms:     "",
			requiredPerms: []string{},
			expectedCode:  200,
		},
		{
			name:          "Has required permission",
			userPerms:     "view_ips,block_ips",
			requiredPerms: []string{"view_ips"},
			expectedCode:  200,
		},
		{
			name:          "Has all required permissions",
			userPerms:     "view_ips,block_ips",
			requiredPerms: []string{"view_ips", "block_ips"},
			expectedCode:  200,
		},
		{
			name:          "Has one of required permissions (OR logic)",
			userPerms:     "view_ips",
			requiredPerms: []string{"view_ips", "block_ips"},
			expectedCode:  200,
		},
		{
			name:          "Has none of required permissions",
			userPerms:     "other_perm",
			requiredPerms: []string{"view_ips", "block_ips"},
			expectedCode:  403,
		},
		{
			name:          "Missing all permissions",
			userPerms:     "",
			requiredPerms: []string{"view_ips"},
			expectedCode:  403,
		},
		{
			name:          "Whitespace in permission string",
			userPerms:     "view_ips, block_ips ",
			requiredPerms: []string{"block_ips"},
			expectedCode:  200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("permissions", tt.userPerms)
				c.Next()
			})
			r.Use(h.PermissionMiddleware(tt.requiredPerms...))
			r.GET("/test", func(c *gin.Context) { c.Status(200) })

			req, _ := http.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("expected %d, got %d", tt.expectedCode, w.Code)
			}
		})
	}
}

func TestAPIHandler_RBACMiddleware_Extended(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAPIHandler(&config.Config{}, nil, nil, nil, nil, nil, nil)

	tests := []struct {
		name         string
		userRole     string
		requiredRole string
		expectedCode int
	}{
		{"Admin accessing admin", "admin", "admin", 200},
		{"Admin accessing operator", "admin", "operator", 200},
		{"Admin accessing viewer", "admin", "viewer", 200},
		{"Operator accessing admin", "operator", "admin", 403},
		{"Operator accessing operator", "operator", "operator", 200},
		{"Operator accessing viewer", "operator", "viewer", 200},
		{"Viewer accessing admin", "viewer", "admin", 403},
		{"Viewer accessing operator", "viewer", "operator", 403},
		{"Viewer accessing viewer", "viewer", "viewer", 200},
		{"Unknown role", "guest", "viewer", 403}, // Assuming default weight is 0 or less than viewer
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("role", tt.userRole)
				c.Next()
			})
			r.Use(h.RBACMiddleware(tt.requiredRole))
			r.GET("/test", func(c *gin.Context) { c.Status(200) })

			req, _ := http.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("expected %d, got %d", tt.expectedCode, w.Code)
			}
		})
	}
}
