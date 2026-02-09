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

func TestAPIHandler_Whitelist(t *testing.T) {
	h, rRepo, _, _, _ := setupTest()

	// Mock data
	rRepo.On("GetWhitelistedIPs").Return(map[string]models.WhitelistEntry{
		"1.2.3.4": {Reason: "Trusted"},
	}, nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request, _ = http.NewRequest("GET", "/whitelist", nil)
	c.Set("username", "admin")
	c.Set("permissions", "all")

	h.Whitelist(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "1.2.3.4")
}

func TestAPIHandler_AddWhitelist(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	// 1. Success - JSON (New standard)
	ipService.On("WhitelistIP", mock.Anything, "5.6.7.8", "manual", "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ip": "5.6.7.8", "reason": "manual"}`
	c.Request, _ = http.NewRequest("POST", "/whitelist/add", bytes.NewBufferString(reqBody))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")

	h.AddWhitelist(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"success"}`, w.Body.String())
	ipService.AssertExpectations(t)

	// 2. Success - Form (Legacy/Fallback)
	ipService.On("WhitelistIP", mock.Anything, "1.2.3.9", "note-val", "admin").Return(nil)

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("POST", "/whitelist/add", bytes.NewBufferString("ip=1.2.3.9&note=note-val"))
	c2.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c2.Set("username", "admin")

	h.AddWhitelist(c2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestAPIHandler_RemoveWhitelist(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	// 1. Success - JSON (New standard from frontend)
	ipService.On("RemoveWhitelist", mock.Anything, "1.2.3.4", "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ip": "1.2.3.4"}`
	c.Request, _ = http.NewRequest("POST", "/whitelist/remove", bytes.NewBufferString(reqBody))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")

	h.RemoveWhitelist(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"success"}`, w.Body.String())
	ipService.AssertExpectations(t)

	// 2. Success - Param (Legacy/Fallback)
	ipService.On("RemoveWhitelist", mock.Anything, "1.2.3.5", "admin").Return(nil)

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Params = gin.Params{{Key: "ip", Value: "1.2.3.5"}}
	c2.Request, _ = http.NewRequest("POST", "/whitelist/remove", nil)
	c2.Set("username", "admin")

	h.RemoveWhitelist(c2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.JSONEq(t, `{"status":"success"}`, w2.Body.String())
}

func TestAPIHandler_JSONWhitelists(t *testing.T) {
	h, rRepo, _, _, _ := setupTest()

	rRepo.On("GetWhitelistedIPs").Return(map[string]models.WhitelistEntry{"9.9.9.9": {Reason: "DNS"}}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/whitelists", nil)

	h.JSONWhitelists(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "9.9.9.9")
}

func TestAPIHandler_RawWhitelists(t *testing.T) {
	h, rRepo, _, _, _ := setupTest()

	rRepo.On("GetWhitelistedIPs").Return(map[string]models.WhitelistEntry{
		"8.8.8.8": {Reason: "Google DNS"},
		"1.1.1.1": {Reason: "Cloudflare DNS"},
	}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// We don't rely on router matching here since we call handler directly
	c.Request, _ = http.NewRequest("GET", "/api/v1/whitelists-raw", nil)

	h.RawWhitelists(c)

	assert.Equal(t, http.StatusOK, w.Code)
	// Since order isn't guaranteed in map iteration, we check for presence
	assert.Contains(t, w.Body.String(), "8.8.8.8")
	assert.Contains(t, w.Body.String(), "1.1.1.1")
}
