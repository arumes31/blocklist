package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAPIHandler_Dashboard(t *testing.T) {
	h, rRepo, pgRepo, _, ipService := setupTest()

	// Mock data
	rRepo.On("GetBlockedIPs").Return(map[string]models.IPEntry{}, nil)
	rRepo.On("GetCache", "persistent_ips_cache", mock.Anything).Return(errors.New("cache miss"))
	pgRepo.On("GetSavedViews", "admin").Return([]models.SavedView{}, nil)
	pgRepo.On("GetPersistentBlocks").Return(map[string]models.IPEntry{}, nil)
	rRepo.On("SetCache", "persistent_ips_cache", mock.Anything, mock.Anything).Return(nil)
	pgRepo.On("GetBlockTrend").Return([]models.BlockTrend{}, nil)

	ipService.On("Stats", mock.Anything).Return(10, 100, 5000, 50,
		[]struct {
			Country string
			Count   int
		}{},
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
	ipService.On("GetExcludedCount", mock.Anything).Return(0)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)

	c.Request, _ = http.NewRequest("GET", "/dashboard", nil)
	c.Set("username", "admin")
	c.Set("permissions", "all")

	h.Dashboard(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Dashboard")
}

func TestAPIHandler_CreateAdmin(t *testing.T) {
	h, _, pgRepo, auth, _ := setupTest()

	auth.On("CreateAdmin", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.AdminAccount{Username: "newadmin", Role: "operator", Permissions: "gui_read"}, nil)
	pgRepo.On("LogAction", "admin", "CREATE_ADMIN", "newadmin", mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqBody := `{"username": "newadmin", "password": "password", "role": "operator", "permissions": "gui_read"}`
	c.Request, _ = http.NewRequest("POST", "/api/admin", bytes.NewBufferString(reqBody))

	c.Set("username", "admin")

	h.CreateAdmin(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPIHandler_DeleteAdmin(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("DeleteAdmin", "oldadmin").Return(nil)
	pgRepo.On("LogAction", "admin", "DELETE_ADMIN", "oldadmin", mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.POST("/api/admin/delete", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("username", "admin")
		_ = session.Save()
		c.Set("username", "admin")
		h.DeleteAdmin(c)
	})

	reqBody := `{"username": "oldadmin"}`
	req, _ := http.NewRequest("POST", "/api/admin/delete", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	pgRepo.AssertExpectations(t)
}

func TestAPIHandler_Stats(t *testing.T) {
	h, _, _, _, ipService := setupTest()

	ipService.On("Stats", mock.Anything).Return(10, 100, 5000, 50,
		[]struct {
			Country string
			Count   int
		}{},
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
	ipService.On("GetExcludedCount", mock.Anything).Return(5)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/stats", nil)

	h.Stats(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, float64(10), resp["hour"])
}

func TestAPIHandler_Settings(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("GetSavedViews", "admin").Return([]models.SavedView{}, nil)
	pgRepo.On("GetAPITokens", "admin").Return([]models.APIToken{}, nil)
	pgRepo.On("GetActiveWebhooks").Return([]models.OutboundWebhook{}, nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request, _ = http.NewRequest("GET", "/settings", nil)
	c.Set("username", "admin")
	c.Set("permissions", "all")

	h.Settings(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPIHandler_AuditLogExplorer(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("GetAuditLogsPaginated", 50, 0, "", "", "").Return([]models.AuditLog{}, 0, nil)

	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request, _ = http.NewRequest("GET", "/audit-logs", nil)
	c.Set("username", "admin")
	c.Set("permissions", "view_logs")

	h.AuditLogExplorer(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

// postAsAdmin runs a handler behind a session that authenticates "admin",
// mirroring how the admin routes execute in production.
func postAsAdmin(h *APIHandler, handler gin.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST(path, func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("username", "admin")
		_ = session.Save()
		c.Set("username", "admin")
		handler(c)
	})
	req, _ := http.NewRequest("POST", path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// The GUIAdmin account must not be strippable of 2FA through this endpoint:
// doing so would let any manage_admins holder disable the primary account's
// second factor and then enrol their own device via self-service setup.
func TestAPIHandler_ChangeAdminTOTP_RejectsGUIAdmin(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	w := postAsAdmin(h, h.ChangeAdminTOTP, "/api/admin/totp", `{"username": "admin"}`)

	assert.Equal(t, http.StatusForbidden, w.Code)
	pgRepo.AssertNotCalled(t, "UpdateAdminToken", "admin", "")
}

func TestAPIHandler_ChangeAdminTOTP_ClearsOtherAdmin(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("UpdateAdminToken", "targetadmin", "").Return(nil)
	pgRepo.On("LogAction", "admin", "RESET_TOTP", "targetadmin", mock.Anything).Return(nil)

	w := postAsAdmin(h, h.ChangeAdminTOTP, "/api/admin/totp", `{"username": "targetadmin"}`)

	assert.Equal(t, http.StatusOK, w.Code)
	pgRepo.AssertExpectations(t)
}

func TestAPIHandler_ChangeAdminTOTP_ReportsUpdateFailure(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("UpdateAdminToken", "targetadmin", "").Return(errors.New("database unavailable"))

	w := postAsAdmin(h, h.ChangeAdminTOTP, "/api/admin/totp", `{"username": "targetadmin"}`)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	pgRepo.AssertNotCalled(t, "LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// A TOTP secret is a credential; serving another account's QR would let the
// caller generate that account's codes indefinitely.
func TestAPIHandler_GetQR_RejectsOtherAccount(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/get_qr/targetadmin", nil)
	c.Params = gin.Params{{Key: "username", Value: "targetadmin"}}
	c.Set("username", "admin")

	h.GetQR(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
	pgRepo.AssertNotCalled(t, "GetAdmin", "targetadmin")
}

func TestAPIHandler_GetQR_RejectsUnenrolledAccount(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("GetAdmin", "admin").Return(&models.AdminAccount{Username: "admin", Token: ""}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/get_qr/admin", nil)
	c.Params = gin.Params{{Key: "username", Value: "admin"}}
	c.Set("username", "admin")

	h.GetQR(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_GetQR_AllowsOwnAccount(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("GetAdmin", "admin").Return(&models.AdminAccount{Username: "admin", Token: "JBSWY3DPEHPK3PXP"}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/get_qr/admin", nil)
	c.Params = gin.Params{{Key: "username", Value: "admin"}}
	c.Set("username", "admin")

	h.GetQR(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "image/png", w.Header().Get("Content-Type"))
}

func TestAPIHandler_GetQR_HandlesMissingAccount(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("GetAdmin", "admin").Return((*models.AdminAccount)(nil), nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/get_qr/admin", nil)
	c.Params = gin.Params{{Key: "username", Value: "admin"}}
	c.Set("username", "admin")

	h.GetQR(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_ChangeAdminPermissions(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("GetAdmin", "targetadmin").Return(&models.AdminAccount{Username: "targetadmin", Permissions: "old_perm"}, nil)
	pgRepo.On("UpdateAdminPermissions", "targetadmin", "new_perm").Return(nil)
	pgRepo.On("LogAction", "admin", "CHANGE_PERMISSIONS", "targetadmin", mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.POST("/api/admin/permissions", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("username", "admin")
		_ = session.Save()
		c.Set("username", "admin")
		h.ChangeAdminPermissions(c)
	})

	reqBody := `{"username": "targetadmin", "permissions": "new_perm"}`
	req, _ := http.NewRequest("POST", "/api/admin/permissions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	pgRepo.AssertExpectations(t)
}
