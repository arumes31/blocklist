package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestOpenAPI_Endpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _, _, _, _ := setupTest()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.OpenAPI(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var spec map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &spec)
	assert.NoError(t, err)

	// Check for core OpenAPI fields
	assert.Equal(t, "3.0.1", spec["openapi"])
	info := spec["info"].(map[string]interface{})
	assert.Equal(t, "Blocklist API", info["title"])

	// Check that paths are present
	paths := spec["paths"].(map[string]interface{})
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "/api/v1/ips")
	assert.Contains(t, paths, "/api/v1/webhook")
}

// The vendored RapiDoc OAuth helper reuses a fixed PKCE verifier and trusts
// any window message. Keep it unreachable: the served spec must not declare
// OAuth2 or OpenID Connect schemes (Bearer tokens are entered directly).
func TestOpenAPI_NoBrowserOAuthSchemes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _, _, _, _ := setupTest()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.OpenAPI(c)

	var spec struct {
		Components struct {
			SecuritySchemes map[string]struct {
				Type string `json:"type"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &spec))
	for name, scheme := range spec.Components.SecuritySchemes {
		assert.NotContains(t, []string{"oauth2", "openIdConnect"}, scheme.Type, "security scheme %s", name)
	}
}
