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

func TestAPIHandler_Excluded(t *testing.T) {
	h, rRepo, pgRepo, _, _ := setupTest()

	rRepo.On("GetExcludedEntries").Return(map[string]models.ExcludedEntry{
		"10.0.0.0/8":      {Value: "10.0.0.0/8", Type: "cidr", Reason: "internal"},
		"api.example.com": {Value: "api.example.com", Type: "fqdn", Reason: "trusted"},
	}, nil)
	pgRepo.On("GetAllExternalSources").Return([]models.ExternalSource{}, nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request, _ = http.NewRequest("GET", "/excluded", nil)
	c.Set("username", "admin")
	c.Set("permissions", "all")

	h.Excluded(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "10.0.0.0/8")
	assert.Contains(t, w.Body.String(), "api.example.com")
}

func TestAPIHandler_AddExcluded(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	// 1. Valid FQDN via JSON
	ipService.On("ExclusionConflicts", mock.Anything, "api.example.com").Return([]string(nil))
	ipService.On("AddExcluded", mock.Anything, "api.example.com", "trusted upstream", "admin", "", false).Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/add_excluded",
		bytes.NewBufferString(`{"value":"api.example.com","reason":"trusted upstream"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")

	h.AddExcluded(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"success"}`, w.Body.String())
	ipService.AssertExpectations(t)

	// 2. Invalid value is rejected before reaching the service.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("POST", "/add_excluded",
		bytes.NewBufferString(`{"value":"not a host!!","reason":"x"}`))
	c2.Request.Header.Set("Content-Type", "application/json")
	c2.Set("username", "admin")

	h.AddExcluded(c2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)

	// 3. Missing reason is rejected.
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	c3.Request, _ = http.NewRequest("POST", "/add_excluded",
		bytes.NewBufferString(`{"value":"1.2.3.4"}`))
	c3.Request.Header.Set("Content-Type", "application/json")
	c3.Set("username", "admin")

	h.AddExcluded(c3)
	assert.Equal(t, http.StatusBadRequest, w3.Code)
}

func TestAPIHandler_RemoveExcluded(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("RemoveExcluded", mock.Anything, "10.0.0.0/8", "admin").Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/remove_excluded",
		bytes.NewBufferString(`{"value":"10.0.0.0/8"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")

	h.RemoveExcluded(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"success"}`, w.Body.String())
	ipService.AssertExpectations(t)
}

func TestIsValidExclusionValue(t *testing.T) {
	valid := []string{"1.2.3.4", "2001:db8::1", "10.0.0.0/8", "api.example.com", "a-b.co.uk"}
	for _, v := range valid {
		if !isValidExclusionValue(v) {
			t.Errorf("expected %q to be a valid exclusion value", v)
		}
	}
	invalid := []string{"", "   ", "not a host!!", "http://x.com", "999.999.999.999/8"}
	for _, v := range invalid {
		if isValidExclusionValue(v) {
			t.Errorf("expected %q to be an invalid exclusion value", v)
		}
	}
}
