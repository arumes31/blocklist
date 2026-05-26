package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAPIHandler_Webhook_CF_Spoofing_Verified(t *testing.T) {
	h, rRepo, pgRepo, _, ipService := setupTest()
	defer rRepo.AssertExpectations(t)
	defer ipService.AssertExpectations(t)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	// Trust 127.0.0.1 as a proxy
	_ = r.SetTrustedProxies([]string{"127.0.0.1"})

	reqBody := `{"act": "selfwhitelist", "reason": "spoof-test"}`
	c.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody))

	// An attacker behind a trusted proxy (127.0.0.1)
	// They provide a valid X-Forwarded-For (which Gin will trust and use as ClientIP)
	c.Request.Header.Set("X-Forwarded-For", "1.1.1.1")
	// BUT they also provide a spoofed CF-Connecting-IP
	c.Request.Header.Set("CF-Connecting-IP", "7.7.7.7")

	c.Request.RemoteAddr = "127.0.0.1:1234"
	c.Set("username", "admin")

	// Current (vulnerable) behavior:
	// 1. clientIP := c.ClientIP() -> returns "1.1.1.1" (because 127.0.0.1 is trusted)
	// 2. remoteIP := "127.0.0.1"
	// 3. remoteIP != clientIP is TRUE ("127.0.0.1" != "1.1.1.1")
	// 4. clientIP = cfIP ("7.7.7.7")
	// Result: IP is detected as "7.7.7.7" (Spoofed!)

	// Desired behavior:
	// IP should be detected as "1.1.1.1" (the one verified by Gin)

	// We expect 1.1.1.1 to be whitelisted, NOT 7.7.7.7
	pgRepo.On("LogAction", mock.Anything, "WHITELIST", "1.1.1.1", "spoof-test").Return(nil)
	rRepo.On("IndexWebhookHit", mock.Anything).Return(nil)
	rRepo.On("WhitelistIP", "1.1.1.1", mock.Anything).Return(nil)
	ipService.On("GetGeoIP", mock.Anything).Return(&models.GeoData{}).Maybe()

	h.Webhook(c)
	assert.Equal(t, http.StatusOK, w.Code)
}
