package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/alicebob/miniredis/v2"
	"strconv"
)

func TestAPIHandler_Health(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	h := NewAPIHandler(cfg, nil, nil, nil, nil, nil, nil)

	r := gin.New()
	r.GET("/health", h.Health)

	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIHandler_Ready(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr, _ := miniredis.Run()
	defer mr.Close()
	
	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	h := NewAPIHandler(&config.Config{}, rRepo, nil, nil, nil, nil, nil)

	r := gin.New()
	r.GET("/ready", h.Ready)

	req, _ := http.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIHandler_OpenAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAPIHandler(&config.Config{}, nil, nil, nil, nil, nil, nil)

	r := gin.New()
	r.GET("/openapi.json", h.OpenAPI)

	req, _ := http.NewRequest("GET", "/openapi.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIHandler_MetricsAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAPIHandler(&config.Config{MetricsAllowedIPs: "127.0.0.1"}, nil, nil, nil, nil, nil, nil)

	r := gin.New()
	r.Use(h.MetricsAuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	// Test allowed IP
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 for allowed IP, got %d", w.Code)
	}

	// Test denied IP
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "1.1.1.1:1234"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 403 {
		t.Errorf("expected 403 for denied IP, got %d", w2.Code)
	}
}

func TestAPIHandler_RBACMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAPIHandler(&config.Config{}, nil, nil, nil, nil, nil, nil)

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

	if w.Code != 403 {
		t.Errorf("expected 403 for insufficient role, got %d", w.Code)
	}
}