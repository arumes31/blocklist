package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/repository"
	"blocklist/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func setupTestRouter(rRepo *repository.RedisRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	// Setup sessions for tests
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("blocklist_session", store))

	cfg := &config.Config{
		GUIAdmin:    "admin",
		GUIPassword: "password",
	}
	
	// Minimal service/handler setup
	ipSvc := service.NewIPService(cfg, rRepo, nil)
	authSvc := service.NewAuthService(nil, rRepo)
	webhookSvc := service.NewWebhookService(nil, rRepo, cfg)
	hub := NewHub(rRepo.GetClient())
	
	h := NewAPIHandler(cfg, rRepo, nil, authSvc, ipSvc, hub, webhookSvc)
	
	// Mock auth session for protected routes
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("logged_in", true)
		session.Set("username", "admin")
		session.Set("role", "admin")
		session.Set("client_ip", "127.0.0.1")
		_ = session.Save()
		c.Next()
	})

	router.POST("/block", h.BlockIP)
	router.POST("/unblock", h.UnblockIP)
	router.POST("/api/v1/webhook", h.Webhook)
	
	return router
}

func TestFunctional_BlockUnblock(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	router := setupTestRouter(rRepo)
	blockReq := map[string]interface{}{
		"ip":      "1.2.3.4",
		"reason":  "functional-test",
		"persist": false,
	}
	body, _ := json.Marshal(blockReq)
	req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost") // CSRF check bypass
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Verify in miniredis
	if !mr.Exists("ips") {
		t.Error("expected 'ips' hash to exist in redis")
	}

	// 2. Test Unblock
	unblockReq := map[string]string{"ip": "1.2.3.4"}
	body, _ = json.Marshal(unblockReq)
	req, _ = http.NewRequest("POST", "/unblock", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost")
	
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestFunctional_Webhook(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	router := setupTestRouter(rRepo)

	webhookReq := map[string]string{
		"ip":       "5.6.7.8",
		"act":      "ban",
		"username": "admin",
		"password": "password",
	}
	body, _ := json.Marshal(webhookReq)
	req, _ := http.NewRequest("POST", "/api/v1/webhook", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}
