package api

import (
	"net/http"

	_ "embed"

	"github.com/gin-gonic/gin"
)

//go:embed openapi.json
var openapiSpec []byte

// OpenAPI returns the OpenAPI spec for the Blocklist API.
func (h *APIHandler) OpenAPI(c *gin.Context) {
	c.Data(http.StatusOK, "application/json", openapiSpec)
}
