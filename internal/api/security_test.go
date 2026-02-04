package api

import (
	"blocklist/internal/models"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSecurity_XSS_Reflected(t *testing.T) {
	// Verify that data from service is properly escaped in templates
	h, rRepo, pgRepo, _, ipService := setupTest()

	// Mock data for Dashboard components
	rRepo.On("GetBlockedIPs").Return(map[string]models.IPEntry{}, nil)
	rRepo.On("GetCache", "persistent_ips_cache", mock.Anything).Return(errors.New("cache miss"))
	pgRepo.On("GetSavedViews", "admin").Return([]models.SavedView{}, nil)
	pgRepo.On("GetPersistentBlocks").Return(map[string]models.IPEntry{}, nil)
	rRepo.On("SetCache", "persistent_ips_cache", mock.Anything, mock.Anything).Return(nil)
	pgRepo.On("GetBlockTrend").Return([]models.BlockTrend{}, nil)

	// Mock malicious input in stats
	ipService.On("Stats", mock.Anything).Return(10, 100, 5000, 50,
		[]struct {
			Country string
			Count   int
		}{
			{Country: "<script>alert('xss')</script>", Count: 1},
		},
		[]struct {
			ASN    uint
			ASNOrg string
			Count  int
		}{},
		[]struct {
			Reason string
			Count  int
		}{},
		5, int64(0), 1, 0, nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request, _ = http.NewRequest("GET", "/dashboard", nil)
	c.Set("username", "admin")
	c.Set("permissions", "all")

	h.Dashboard(c)

	assert.Equal(t, http.StatusOK, w.Code)
	// Assert script tags are escaped
	assert.Contains(t, w.Body.String(), "&lt;script&gt;alert")
	assert.NotContains(t, w.Body.String(), "<script>alert")
}
