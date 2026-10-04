package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"blocklist/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAPIHandler_ThreatMapBootstrap(t *testing.T) {
	h, redis, postgres, _, service := setupTest()
	redis.Test(t)
	postgres.Test(t)
	service.Test(t)
	const hostileReason = `</script><script>alert("blocked")</script>`
	mockThreatMapStats(service, hostileReason, nil)
	postgres.On("GetBlockTrend").Return([]models.BlockTrend{
		{Hour: "2026-10-04T08:00:00Z", Count: 7},
		{Hour: "2026-10-04T09:00:00Z", Count: 0},
	}, nil).Once()

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/threat-map", nil)
	c.Set("username", "analyst")
	c.Set("permissions", "view_ips,view_stats")
	h.ThreatMap(c)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `src="/cd/logo.png"`)
	for _, destination := range []string{"/dashboard", "/whitelist", "/excluded", "/audit-logs", "/settings", "/docs", "/logout"} {
		assert.Contains(t, w.Body.String(), `href="`+destination+`"`)
	}
	assert.Regexp(t, `href="/threat-map"[^>]*aria-current="page"`, w.Body.String())
	assert.Regexp(t, `id="toggle-all-blocked"[^>]*\bchecked\b`, w.Body.String())
	bootstrap := threatMapBootstrap(t, w.Body.String())
	assert.Equal(t, true, bootstrap["stats_allowed"])
	assert.Equal(t, float64(50), bootstrap["total"], "active count must not use the lifetime total")
	assert.Equal(t, float64(10), bootstrap["hour"])
	assert.Equal(t, float64(100), bootstrap["day"])
	assert.Equal(t, float64(3), bootstrap["blocks_minute"])
	assert.Equal(t, float64(2), bootstrap["whitelisted"])
	assert.Equal(t, []any{map[string]any{"country": "Austria", "count": float64(12)}}, bootstrap["top_countries"])
	assert.Equal(t, []any{map[string]any{"reason": hostileReason, "count": float64(8)}}, bootstrap["top_reasons"])
	assert.Equal(t, true, bootstrap["trend_available"])
	assert.Equal(t, []any{
		map[string]any{"x": "2026-10-04T08:00:00Z", "y": float64(7)},
		map[string]any{"x": "2026-10-04T09:00:00Z", "y": float64(0)},
	}, bootstrap["trend"])
	assert.NotContains(t, w.Body.String(), hostileReason, "a reason must not close the bootstrap script element")
	redis.AssertNotCalled(t, "GetBlockedIPs")
	postgres.AssertNotCalled(t, "GetPersistentBlocks")
	postgres.AssertExpectations(t)
	service.AssertExpectations(t)
}

func TestAPIHandler_ThreatMapStatsPermissions(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		permissions string
		missing     bool
		allowed     bool
	}{
		{name: "granular permission", username: "analyst", permissions: "view_ips, view_stats ", allowed: true},
		{name: "system administrator", username: "admin", permissions: "view_ips", allowed: true},
		{name: "map only", username: "analyst", permissions: "view_ips"},
		{name: "partial permission does not match", username: "analyst", permissions: "view_ips,view_stats_extra"},
		{name: "all is not a wildcard", username: "analyst", permissions: "all"},
		{name: "missing permissions", username: "analyst", missing: true},
		{name: "administrator requires permission context", username: "admin", missing: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, redis, postgres, _, service := setupTest()
			redis.Test(t)
			postgres.Test(t)
			service.Test(t)
			if tt.allowed {
				mockThreatMapStats(service, "scanner", nil)
				postgres.On("GetBlockTrend").Return([]models.BlockTrend{}, nil).Once()
			}

			w := httptest.NewRecorder()
			c, _ := setupHTMLTest(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/threat-map", nil)
			c.Set("username", tt.username)
			if !tt.missing {
				c.Set("permissions", tt.permissions)
			}
			h.ThreatMap(c)

			require.Equal(t, http.StatusOK, w.Code)
			bootstrap := threatMapBootstrap(t, w.Body.String())
			assert.Equal(t, tt.allowed, bootstrap["stats_allowed"])
			if tt.allowed {
				assert.Equal(t, true, bootstrap["trend_available"], "an empty successful trend is available")
			} else {
				for _, field := range []string{"total", "hour", "day", "blocks_minute", "whitelisted"} {
					assert.Contains(t, bootstrap, field)
					assert.Nil(t, bootstrap[field], field)
				}
				for _, field := range []string{"top_countries", "top_reasons", "trend"} {
					assert.Equal(t, []any{}, bootstrap[field], field)
				}
				assert.Equal(t, false, bootstrap["trend_available"])
				service.AssertNotCalled(t, "Stats", mock.Anything)
				postgres.AssertNotCalled(t, "GetBlockTrend")
			}
			redis.AssertNotCalled(t, "GetBlockedIPs")
			postgres.AssertNotCalled(t, "GetPersistentBlocks")
			postgres.AssertExpectations(t)
			service.AssertExpectations(t)
		})
	}
}

func TestAPIHandler_ThreatMapTrendFailure(t *testing.T) {
	h, _, postgres, _, service := setupTest()
	mockThreatMapStats(service, "scanner", nil)
	postgres.On("GetBlockTrend").Return(
		[]models.BlockTrend{{Hour: "2026-10-04T08:00:00Z", Count: 7}},
		errors.New("database unavailable"),
	).Once()

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/threat-map", nil)
	c.Set("username", "admin")
	c.Set("permissions", "view_ips")
	h.ThreatMap(c)

	require.Equal(t, http.StatusOK, w.Code)
	bootstrap := threatMapBootstrap(t, w.Body.String())
	assert.Equal(t, false, bootstrap["trend_available"])
	assert.Equal(t, []any{}, bootstrap["trend"], "failed or partial trends must not be presented as complete")
	assert.Equal(t, float64(50), bootstrap["total"])
	assert.NotContains(t, w.Body.String(), "database unavailable")
	postgres.AssertExpectations(t)
	service.AssertExpectations(t)
}

func TestAPIHandler_ThreatMapStatsFailure(t *testing.T) {
	h, redis, postgres, _, service := setupTest()
	mockThreatMapStats(service, "scanner", errors.New("private database error"))

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/threat-map", nil)
	c.Set("username", "admin")
	c.Set("permissions", "view_ips")
	h.ThreatMap(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "failed to fetch threat map stats", w.Body.String())
	redis.AssertNotCalled(t, "GetBlockedIPs")
	postgres.AssertNotCalled(t, "GetPersistentBlocks")
	postgres.AssertNotCalled(t, "GetBlockTrend")
	service.AssertExpectations(t)
}

func mockThreatMapStats(service *MockIPService, reason string, err error) {
	service.On("Stats", mock.Anything).Return(10, 100, 5000, 50,
		[]struct {
			Country string
			Count   int
		}{{Country: "Austria", Count: 12}},
		[]struct {
			ASN    uint
			ASNOrg string
			Count  int
		}{},
		[]struct {
			Reason string
			Count  int
		}{{Reason: reason, Count: 8}},
		5, int64(0), 3, 2, err,
	).Once()
}

func threatMapBootstrap(t *testing.T, body string) map[string]any {
	t.Helper()
	script := regexp.MustCompile(`(?s)<script\b[^>]*\bid="threat-map-bootstrap"[^>]*>(.*?)</script>`).FindStringSubmatch(body)
	require.Len(t, script, 2, "rendered threat map must include its JSON bootstrap")
	var bootstrap map[string]any
	require.NoError(t, json.Unmarshal([]byte(script[1]), &bootstrap))
	return bootstrap
}
