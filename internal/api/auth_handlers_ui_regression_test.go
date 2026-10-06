package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAPIHandler_UpdateAPITokenPermissionsUI(t *testing.T) {
	for _, tt := range []struct {
		name        string
		id          string
		body        string
		permissions string
		writeErr    error
		status      int
		wantWrite   bool
	}{
		{
			name: "save selected scopes", id: "42", body: `{"permissions":"view_ips,unblock_ips"}`,
			permissions: "view_ips,unblock_ips", status: http.StatusOK, wantWrite: true,
		},
		{
			name: "clear all scopes", id: "42", body: `{"permissions":""}`,
			status: http.StatusOK, wantWrite: true,
		},
		{
			name: "cannot select rights the owner lacks", id: "42", body: `{"permissions":"manage_admins"}`,
			status: http.StatusForbidden,
		},
		{name: "bad ID", id: "invalid", body: `{"permissions":"view_ips"}`, status: http.StatusBadRequest},
		{name: "invalid JSON", id: "42", body: `{`, status: http.StatusBadRequest},
		{
			name: "storage failure is visible", id: "42", body: `{"permissions":"view_ips"}`,
			permissions: "view_ips", writeErr: errors.New("private token storage detail"),
			status: http.StatusInternalServerError, wantWrite: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			if tt.wantWrite {
				pg.On("UpdateAPITokenPermissions", 42, "member", tt.permissions).Return(tt.writeErr).Once()
				if tt.writeErr == nil {
					pg.On("LogAction", "member", "UPDATE_TOKEN_PERMS", "42", tt.permissions).Return(nil).Once()
				}
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "member")
			c.Set("permissions", "view_ips,unblock_ips,manage_api_tokens")
			c.Params = gin.Params{{Key: "id", Value: tt.id}}
			c.Request = httptest.NewRequest(http.MethodPut, "/api/tokens/"+tt.id, strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			h.UpdateAPITokenPermissions(c)
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d: %s", w.Code, tt.status, w.Body)
			}
			if strings.Contains(w.Body.String(), "private token storage detail") {
				t.Fatal("storage details leaked to UI")
			}
			pg.AssertExpectations(t)
		})
	}
}

func TestAPIHandler_DeleteAPITokenUI(t *testing.T) {
	for _, tt := range []struct {
		name   string
		id     string
		status int
	}{
		{name: "revoke own token", id: "42", status: http.StatusOK},
		{name: "reject invalid ID", id: "invalid", status: http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			if tt.status == http.StatusOK {
				// Owner-scoped deletion must not call the workspace-wide revoke method.
				pg.On("DeleteAPIToken", 42, "member").Return(nil).Once()
				pg.On("LogAction", "member", "DELETE_TOKEN", "42", "API Token deleted").Return(nil).Once()
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "member")
			c.Params = gin.Params{{Key: "id", Value: tt.id}}
			c.Request = httptest.NewRequest(http.MethodDelete, "/api/tokens/"+tt.id, nil)
			h.DeleteAPIToken(c)
			c.Writer.WriteHeaderNow()
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d", w.Code, tt.status)
			}
			pg.AssertExpectations(t)
		})
	}
}

func TestAPIHandler_AdminRevokeAPITokenUIRestrictions(t *testing.T) {
	for _, tt := range []struct {
		name        string
		id          string
		permissions string
		status      int
	}{
		{name: "view is not revoke", id: "42", permissions: "view_api_tokens", status: http.StatusForbidden},
		{
			name: "own token management is not global", id: "42", permissions: "manage_api_tokens",
			status: http.StatusForbidden,
		},
		{name: "invalid ID", id: "invalid", permissions: "manage_global_tokens", status: http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "member")
			c.Set("permissions", tt.permissions)
			c.Params = gin.Params{{Key: "id", Value: tt.id}}
			c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/tokens/"+tt.id, nil)
			h.AdminRevokeAPIToken(c)
			c.Writer.WriteHeaderNow()
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d", w.Code, tt.status)
			}
			pg.AssertExpectations(t)
		})
	}
}
