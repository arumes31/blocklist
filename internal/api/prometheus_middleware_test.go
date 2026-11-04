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

	t.Run("tracked route pattern", func(t *testing.T) {
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

	t.Run("unknown route", func(t *testing.T) {
		r := gin.New()
		r.Use(h.PrometheusMiddleware())

		initialCount := testutil.CollectAndCount(metrics.MetricHttpDuration)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/not-found", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, initialCount+1, testutil.CollectAndCount(metrics.MetricHttpDuration), "Metric should be incremented for unknown routes")
	})

	t.Run("aborted request", func(t *testing.T) {
		r := gin.New()
		r.Use(h.PrometheusMiddleware())
		r.GET("/aborted", func(c *gin.Context) {
			c.AbortWithStatus(http.StatusForbidden)
		})

		initialCount := testutil.CollectAndCount(metrics.MetricHttpDuration)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/aborted", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, initialCount+1, testutil.CollectAndCount(metrics.MetricHttpDuration))
	})

	t.Run("extension methods share one label", func(t *testing.T) {
		r := gin.New()
		r.Use(h.PrometheusMiddleware())

		send := func(method string) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(method, "/method-cardinality", nil)
			r.ServeHTTP(w, req)
		}
		send("FOO1")
		initialCount := testutil.CollectAndCount(metrics.MetricHttpDuration)
		for _, method := range []string{"FOO2", "BAR", "PROPFIND"} {
			send(method)
		}
		assert.Equal(t, initialCount, testutil.CollectAndCount(metrics.MetricHttpDuration), "unknown methods must not add series")
	})
}
