package api

import (
	"blocklist/internal/models"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAPIHandler_BlockIP(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	// 1. Success Case
	entry := &models.IPEntry{} // Valid entry for test
	ipService.On("BlockIP", mock.Anything, "1.2.3.4", "spam", "admin", "127.0.0.1", true, time.Duration(0)).Return(entry, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ip": "1.2.3.4", "reason": "spam", "persist": true}`
	c.Request, _ = http.NewRequest("POST", "/api/block", bytes.NewBufferString(reqBody))
	c.Request.RemoteAddr = "127.0.0.1:1234"
	c.Set("username", "admin")

	h.BlockIP(c)

	assert.Equal(t, http.StatusOK, w.Code)
	ipService.AssertExpectations(t)

	// 2. Invalid IP
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	reqBody2 := `{"ip": "invalid-ip"}`
	c2.Request, _ = http.NewRequest("POST", "/api/block", bytes.NewBufferString(reqBody2))
	c2.Set("username", "admin")

	h.BlockIP(c2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)

	// 3. Service Error
	ipService.On("BlockIP", mock.Anything, "5.6.7.8", "", "admin", "127.0.0.1", false, time.Duration(0)).Return(nil, errors.New("db error"))

	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	reqBody3 := `{"ip": "5.6.7.8"}`
	c3.Request, _ = http.NewRequest("POST", "/api/block", bytes.NewBufferString(reqBody3))
	c3.Request.RemoteAddr = "127.0.0.1:1234"
	c3.Set("username", "admin")

	h.BlockIP(c3)
	assert.Equal(t, http.StatusInternalServerError, w3.Code)
}

func TestAPIHandler_UnblockIP(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	// 1. Success
	ipService.On("UnblockIP", mock.Anything, "1.2.3.4", "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ip": "1.2.3.4"}`
	c.Request, _ = http.NewRequest("POST", "/api/unblock", bytes.NewBufferString(reqBody))
	c.Set("username", "admin")

	h.UnblockIP(c)

	assert.Equal(t, http.StatusOK, w.Code)
	ipService.AssertExpectations(t)

	// 2. Service Error
	ipService.On("UnblockIP", mock.Anything, "5.6.7.8", "admin").Return(errors.New("fail"))

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	reqBody2 := `{"ip": "5.6.7.8"}`
	c2.Request, _ = http.NewRequest("POST", "/api/unblock", bytes.NewBufferString(reqBody2))
	c2.Set("username", "admin")

	h.UnblockIP(c2)
	assert.Equal(t, http.StatusInternalServerError, w2.Code)
}

func TestAPIHandler_BulkBlock(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("BulkBlock", mock.Anything, []string{"1.1.1.1", "2.2.2.2"}, "botnet", "admin", "127.0.0.1", true, 0).Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ips": ["1.1.1.1", "2.2.2.2"], "reason": "botnet", "persist": true}`
	c.Request, _ = http.NewRequest("POST", "/api/bulk-block", bytes.NewBufferString(reqBody))
	c.Request.RemoteAddr = "127.0.0.1:1234"
	c.Set("username", "admin")

	h.BulkBlock(c)

	assert.Equal(t, http.StatusOK, w.Code)
	ipService.AssertExpectations(t)
}

func TestAPIHandler_BulkUnblock(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("BulkUnblock", mock.Anything, []string{"1.1.1.1"}, "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"ips": ["1.1.1.1"]}`
	c.Request, _ = http.NewRequest("POST", "/api/bulk-unblock", bytes.NewBufferString(reqBody))
	c.Set("username", "admin")

	h.BulkUnblock(c)

	assert.Equal(t, http.StatusOK, w.Code)
	ipService.AssertExpectations(t)
}

func TestAPIHandler_GetIPDetails(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	expected := map[string]interface{}{"ip": "1.2.3.4", "history": []interface{}{}}
	ipService.On("GetIPDetails", mock.Anything, "1.2.3.4").Return(expected, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "ip", Value: "1.2.3.4"}}
	c.Request, _ = http.NewRequest("GET", "/api/ip/1.2.3.4", nil)

	h.GetIPDetails(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "1.2.3.4", resp["ip"])
}

func TestAPIHandler_ExportIPs(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	// Mock data return
	ipService.On("ExportIPs", mock.Anything, "", "", "", "", "").Return([]map[string]interface{}{}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/export?format=csv", nil)

	h.ExportIPs(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
}
