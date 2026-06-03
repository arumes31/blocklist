package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/metrics"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAPIHandler_PrometheusMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _, _, _, _ := setupTest()

	t.Run("tracked path", func(t *testing.T) {
		r := gin.New()
		r.Use(h.PrometheusMiddleware())
		r.GET("/test/:id", func(c *gin.Context) {
			c.Status(http.StatusAccepted)
		})

		initialCount := testutil.CollectAndCount(metrics.MetricHttpDuration)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test/123", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.Equal(t, initialCount+1, testutil.CollectAndCount(metrics.MetricHttpDuration), "Metric should be incremented")
	})

	t.Run("unknown path", func(t *testing.T) {
		r := gin.New()
		r.Use(h.PrometheusMiddleware())
		// No route defined, so FullPath() should be empty in the middleware

		initialCount := testutil.CollectAndCount(metrics.MetricHttpDuration)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/not-found", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, initialCount+1, testutil.CollectAndCount(metrics.MetricHttpDuration), "Metric should be incremented even for 404")
	})
}
