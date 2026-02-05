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

	ipService.On("WhitelistIP", mock.Anything, "5.6.7.8", "manual", "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)

	form := "ip=5.6.7.8&note=manual"
	c.Request, _ = http.NewRequest("POST", "/whitelist/add", bytes.NewBufferString(form))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Set("username", "admin")

	h.AddWhitelist(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"success"}`, w.Body.String())
}

func TestAPIHandler_RemoveWhitelist(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("RemoveWhitelist", mock.Anything, "1.2.3.4", "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "ip", Value: "1.2.3.4"}}
	c.Request, _ = http.NewRequest("DELETE", "/whitelist/remove/1.2.3.4", nil)
	c.Set("username", "admin")

	h.RemoveWhitelist(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"success"}`, w.Body.String())
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
