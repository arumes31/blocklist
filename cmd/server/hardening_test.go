package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestBodyLimitMiddlewareRejectsOversizedBodies(t *testing.T) {
	r := gin.New()
	r.Use(bodyLimitMiddleware(16))
	r.POST("/", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})
	for size, want := range map[int]int{16: http.StatusOK, 17: http.StatusRequestEntityTooLarge} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, size))))
		assert.Equal(t, want, w.Code, "body of %d bytes", size)
	}
}

func TestHTTPSRedirectIgnoresSpoofedForwardedProto(t *testing.T) {
	r := gin.New()
	r.Use(httpsRedirectMiddleware(security.ParsePrefixes([]string{"10.0.0.5/32"})))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	spoofed := httptest.NewRequest(http.MethodGet, "/", nil)
	spoofed.RemoteAddr = "198.51.100.1:1234"
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, spoofed)
	assert.Equal(t, http.StatusPermanentRedirect, w.Code, "untrusted clients cannot skip the redirect")

	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.RemoteAddr = "10.0.0.5:1234"
	proxied.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, proxied)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHSTSSentBehindTrustedTLSProxy(t *testing.T) {
	r := gin.New()
	r.Use(securityHeadersMiddleware(&config.Config{ForceHTTPS: true, TrustedProxies: "10.0.0.5"}))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
}
