package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupAuthTest() (*APIHandler, *MockAuthService, *MockPostgresRepo) {
	h, _, pg, auth, _ := setupTest()
	return h, auth, pg
}

func TestAPIHandler_Login_Success(t *testing.T) {
	h, auth, pg := setupAuthTest()

	// Mock DB lookups
	pg.On("GetAdmin", "admin").Return(&models.AdminAccount{
		Username: "admin",
		Role:     "admin",
		Token:    "secret",
	}, nil)
	pg.On("LogAction", "admin", "LOGIN_SUCCESS", mock.Anything, "").Return(nil)

	// Mock Auth Service
	auth.On("CheckAuth", "admin", "password", "123456").Return(true)

	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST("/login", h.Login)

	w := httptest.NewRecorder()
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "password")
	form.Add("totp", "123456")
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code) // Redirect to dashboard
	assert.Equal(t, "/dashboard", w.Header().Get("Location"))
}

func TestAPIHandler_Login_Failure(t *testing.T) {
	h, auth, pg := setupAuthTest()

	pg.On("GetAdmin", "admin").Return(&models.AdminAccount{Username: "admin"}, nil)
	pg.On("LogAction", "admin", "LOGIN_FAILURE", mock.Anything, mock.Anything).Return(nil)
	auth.On("CheckAuth", "admin", "wrong", "000000").Return(false)

	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)

	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST("/login", h.Login)
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "wrong")
	form.Add("totp", "000000")
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code) // Renders login page with error
	assert.Contains(t, w.Body.String(), "Invalid credentials")
}

func TestAPIHandler_Logout(t *testing.T) {
	h, _, _ := setupAuthTest()

	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.GET("/logout", h.Logout)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/logout", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestAPIHandler_CreateAPIToken(t *testing.T) {
	h, _, pg := setupAuthTest()

	pg.On("CreateAPIToken", mock.Anything).Return(nil)
	pg.On("GetAPITokens", "admin").Return([]models.APIToken{}, nil)
	pg.On("LogAction", "admin", "CREATE_TOKEN", "New Token", mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)

	r.POST("/api/tokens", func(c *gin.Context) {
		c.Set("username", "admin")
		c.Set("role", "admin")
		c.Set("permissions", "all")
		h.CreateAPIToken(c)
	})

	form := url.Values{}
	form.Add("name", "New Token")
	form.Add("permissions", "block_ips")
	req, _ := http.NewRequest("POST", "/api/tokens", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("HX-Trigger"), "newToken")
}

func TestAPIHandler_RevokeAPIToken(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("DeleteAPITokenByID", 123).Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "123"}}
	c.Request, _ = http.NewRequest("DELETE", "/api/tokens/123", nil)
	// Add permission for admin revoke logic
	c.Set("permissions", "manage_global_tokens")
	c.Set("username", "admin")
	pgRepo.On("LogAction", "admin", "ADMIN_REVOKE_TOKEN", "123", mock.Anything).Return(nil)
	h.AdminRevokeAPIToken(c)

	assert.Equal(t, http.StatusOK, w.Code)
}
