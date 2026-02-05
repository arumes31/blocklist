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

func TestAPIHandler_Webhook(t *testing.T) {
	h, rRepo, pgRepo, _, ipService := setupTest()
	defer rRepo.AssertExpectations(t)
	defer ipService.AssertExpectations(t)

	// 1. Success - Ban
	ipService.On("IsValidIP", "1.2.3.4").Return(true)
	ipService.On("GetGeoIP", mock.Anything).Return(&models.GeoData{}).Maybe()
	ipService.On("CalculateThreatScore", "1.2.3.4", "spam").Return(50)

	rRepo.On("IndexWebhookHit", mock.Anything).Return(nil)
	rRepo.On("ExecBlockAtomic", "1.2.3.4", mock.MatchedBy(func(e models.IPEntry) bool {
		return e.Reason == "spam"
	}), mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ip": "1.2.3.4", "act": "ban", "reason": "spam", "persist": false}`
	c.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody))
	c.Request.RemoteAddr = "127.0.0.1:1234"
	c.Set("username", "admin")

	h.Webhook(c)
	assert.Equal(t, http.StatusOK, w.Code)

	// 2. Success - Unban (Note: current handler only logs and broadcasts)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	reqBody2 := `{"ip": "5.6.7.8", "act": "unban"}`
	c2.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody2))
	c2.Request.RemoteAddr = "127.0.0.1:1234"
	c2.Set("username", "admin")

	pgRepo.On("LogAction", mock.Anything, "UNBLOCK", "5.6.7.8", "webhook unban").Return(nil)
	ipService.On("UnblockIP", mock.Anything, "5.6.7.8", "admin").Return(nil)

	h.Webhook(c2)
	assert.Equal(t, http.StatusOK, w2.Code)

	// 3. Success - Unban with alias
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	reqBody3 := `{"ip": "9.9.9.9", "act": "unban-ip"}`
	c3.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody3))
	c3.Request.RemoteAddr = "127.0.0.1:1234"
	c3.Set("username", "admin")

	pgRepo.On("LogAction", mock.Anything, "UNBLOCK", "9.9.9.9", "webhook unban").Return(nil)
	ipService.On("UnblockIP", mock.Anything, "9.9.9.9", "admin").Return(nil)

	h.Webhook(c3)
	assert.Equal(t, http.StatusOK, w3.Code)

	// 4. Success - Self-Whitelist
	w4 := httptest.NewRecorder()
	c4, _ := gin.CreateTestContext(w4)
	reqBody4 := `{"act": "selfwhitelist", "reason": "me"}`
	c4.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody4))
	c4.Request.RemoteAddr = "127.0.0.1:5555"
	c4.Set("username", "admin")

	rRepo.On("WhitelistIP", "127.0.0.1", mock.MatchedBy(func(e models.WhitelistEntry) bool {
		return e.ExpiresAt != ""
	})).Return(nil)

	h.Webhook(c4)
	assert.Equal(t, http.StatusOK, w4.Code)
}

func TestAPIHandler_Webhook_Security(t *testing.T) {
	h, rRepo, _, _, ipService := setupTest()

	// 1. Invalid IP Format
	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	reqBody1 := `{"ip": "not-an-ip", "act": "ban"}`
	c1.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody1))
	c1.Request.RemoteAddr = "127.0.0.1:1234"
	c1.Set("username", "admin")

	h.Webhook(c1)
	assert.Equal(t, http.StatusBadRequest, w1.Code)

	// 2. CF-Connecting-IP Spoofing (Untrusted Proxy)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	reqBody2 := `{"act": "selfwhitelist", "reason": "spoof"}`
	c2.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody2))
	c2.Request.Header.Set("CF-Connecting-IP", "5.5.5.5")
	c2.Request.RemoteAddr = "1.2.3.4:1234"
	c1.Set("username", "admin")

	// IP detected as 1.2.3.4 (RemoteAddr) because CF header is ignored when not behind a verified proxy
	rRepo.On("IndexWebhookHit", mock.Anything).Return(nil)
	rRepo.On("WhitelistIP", "1.2.3.4", mock.Anything).Return(nil)
	ipService.On("GetGeoIP", mock.Anything).Return(&models.GeoData{}).Maybe()

	// Wait, I used c1 accidentally in line 107 in my scratchpad, fixing it to c2.
	c2.Set("username", "admin")

	h.Webhook(c2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestAPIHandler_Webhook_IPDetection(t *testing.T) {
	h, rRepo, _, _, ipService := setupTest()
	defer rRepo.AssertExpectations(t)
	defer ipService.AssertExpectations(t)

	// 1. Cloudflare Header (CF-Connecting-IP) - Trusted Proxy
	w1 := httptest.NewRecorder()
	c1, r := gin.CreateTestContext(w1)
	_ = r.SetTrustedProxies([]string{"127.0.0.1"})

	reqBody1 := `{"act": "selfwhitelist", "reason": "cf-test"}`
	c1.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody1))
	c1.Request.Header.Set("CF-Connecting-IP", "2.2.2.2")
	c1.Request.Header.Set("X-Forwarded-For", "2.2.2.2") // To trigger Gin to trust the proxy
	c1.Request.RemoteAddr = "127.0.0.1:1234"
	c1.Set("username", "admin")

	// IP detected as 2.2.2.2
	rRepo.On("IndexWebhookHit", mock.Anything).Return(nil)
	rRepo.On("WhitelistIP", "2.2.2.2", mock.MatchedBy(func(e models.WhitelistEntry) bool {
		return e.Reason == "cf-test"
	})).Return(nil)
	ipService.On("GetGeoIP", mock.Anything).Return(&models.GeoData{}).Maybe()

	h.Webhook(c1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// 2. X-Forwarded-For Header - Untrusted
	w2 := httptest.NewRecorder()
	c2, r2 := gin.CreateTestContext(w2)
	_ = r2.SetTrustedProxies([]string{}) // Don't trust anyone

	reqBody2 := `{"act": "selfwhitelist", "reason": "xff-test"}`
	c2.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody2))
	c2.Request.Header.Set("X-Forwarded-For", "3.3.3.3, 10.0.0.1")
	c2.Request.RemoteAddr = "1.1.1.1:1234"
	c2.Set("username", "admin")

	// c.ClientIP() will be 1.1.1.1 because proxy is not trusted
	rRepo.On("WhitelistIP", "1.1.1.1", mock.Anything).Return(nil)

	h.Webhook(c2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestAPIHandler_Webhook_BanTTL(t *testing.T) {
	h, rRepo, _, _, ipService := setupTest()
	defer rRepo.AssertExpectations(t)
	defer ipService.AssertExpectations(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"act": "ban", "ip": "4.4.4.4", "reason": "ttl-test"}`
	c.Request, _ = http.NewRequest("POST", "/api/webhook", bytes.NewBufferString(reqBody))
	c.Request.RemoteAddr = "127.0.0.1:1234"
	c.Set("username", "admin")

	ipService.On("IsValidIP", "4.4.4.4").Return(true)
	ipService.On("GetGeoIP", mock.Anything).Return(&models.GeoData{}).Maybe()
	ipService.On("CalculateThreatScore", "4.4.4.4", "ttl-test").Return(0)
	rRepo.On("IndexWebhookHit", mock.Anything).Return(nil)

	// Expect WhitelistIP NOT to be called, but ExecBlockAtomic SHOULD be called with an entry that has ExpiresAt
	rRepo.On("ExecBlockAtomic", "4.4.4.4", mock.MatchedBy(func(e models.IPEntry) bool {
		return e.ExpiresAt != "" // Verify TTL is set
	}), mock.Anything).Return(nil)

	h.Webhook(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPIHandler_AddOutboundWebhook(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("CreateOutboundWebhook", mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request, _ = http.NewRequest("POST", "/webhooks", nil)
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.AddOutboundWebhook(c)
	assert.Equal(t, http.StatusOK, w.Code)
}
