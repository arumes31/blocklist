package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/gin-gonic/gin"
)

type roleUIRepository struct {
	roleMutationRepository
	savedRole models.AccessRole
	assigned  *models.AdminAccount
	actor     string
	writeErr  error
}

func (r *roleUIRepository) SaveRole(_ context.Context, role models.AccessRole, actor string) error {
	r.saved = true
	r.savedRole, r.actor = role, actor
	return r.writeErr
}

func (r *roleUIRepository) AssignAdminRole(_ context.Context, account models.AdminAccount, actor string) error {
	r.assigned, r.actor = &account, actor
	return r.writeErr
}

func TestAPIHandler_SaveRoleUIValidation(t *testing.T) {
	// setupTest changes Gin's global mode, so these cases intentionally run sequentially.
	for _, tt := range []struct {
		name      string
		body      string
		method    string
		writeErr  error
		status    int
		wantWrite bool
	}{
		{
			name: "create trims text and normalizes checkbox permissions",
			body: `{"id":"custom","name":"  Custom  ","description":"  Description  ",` +
				`"permissions":"view_ips, gui_read,view_ips","revision":99}`,
			status: http.StatusOK, wantWrite: true,
		},
		{
			name:   "update uses immutable URL key",
			body:   `{"id":"ignored","name":"Custom","permissions":"gui_read,view_ips","revision":2}`,
			method: http.MethodPut, status: http.StatusOK, wantWrite: true,
		},
		{name: "malformed JSON", body: `{`, status: http.StatusBadRequest},
		{name: "blank name", body: `{"id":"custom","name":" "}`, status: http.StatusBadRequest},
		{name: "invalid role key", body: `{"id":"Bad key","name":"Custom"}`, status: http.StatusBadRequest},
		{
			name:   "unknown checkbox permission",
			body:   `{"id":"custom","name":"Custom","permissions":"unknown_permission"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "name too long",
			body:   `{"id":"custom","name":"` + strings.Repeat("a", 81) + `"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "description too long",
			body:   `{"id":"custom","name":"Custom","description":"` + strings.Repeat("a", 501) + `"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "oversized request",
			body:   `{"id":"custom","name":"` + strings.Repeat("a", 17000) + `"}`,
			status: http.StatusBadRequest,
		},
		{
			name: "update without revision",
			body: `{"id":"custom","name":"Custom"}`, method: http.MethodPut,
			status: http.StatusBadRequest,
		},
		{
			name: "concurrent change reported to dialog",
			body: `{"id":"custom","name":"Custom"}`, writeErr: repository.ErrIdentityConflict,
			status: http.StatusConflict, wantWrite: true,
		},
		{
			name: "storage error does not claim success",
			body: `{"id":"custom","name":"Custom"}`, writeErr: errors.New("private storage detail"),
			status: http.StatusInternalServerError, wantWrite: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, _, _ := setupTest()
			repo := &roleUIRepository{
				roleMutationRepository: roleMutationRepository{
					role: models.AccessRole{ID: "custom", Permissions: "gui_read,view_ips", Revision: 2},
				},
				writeErr: tt.writeErr,
			}
			h.identityRepo = repo
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "role-editor")
			c.Set("permissions", models.AllPermissions())
			c.Params = gin.Params{{Key: "id", Value: "custom"}}
			c.Request = httptest.NewRequest(method, "/api/v1/roles/custom", strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			h.SaveRole(c)
			if w.Code != tt.status || repo.saved != tt.wantWrite {
				t.Fatalf("status=%d write=%v, want %d/%v: %s", w.Code, repo.saved, tt.status, tt.wantWrite, w.Body)
			}
			if strings.Contains(w.Body.String(), "private storage detail") {
				t.Fatal("storage details leaked to UI")
			}
			if w.Code != http.StatusOK {
				return
			}
			if repo.savedRole.ID != "custom" || repo.savedRole.Name != "Custom" || repo.actor != "role-editor" {
				t.Fatalf("unexpected saved role or actor: %+v / %q", repo.savedRole, repo.actor)
			}
			if repo.savedRole.Permissions != "gui_read,view_ips" {
				t.Fatalf("permissions not normalized: %q", repo.savedRole.Permissions)
			}
			if method == http.MethodPost && (repo.savedRole.Revision != 0 || repo.savedRole.Description != "Description") {
				t.Fatalf("unexpected creation values: %+v", repo.savedRole)
			}
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response["status"] != "success" {
				t.Fatalf("dialog did not receive success: %s", w.Body)
			}
		})
	}
}

func TestAPIHandler_DeleteRoleUIFailures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		text   string
	}{
		{name: "built-in", err: repository.ErrRoleProtected, status: http.StatusConflict, text: "cannot be deleted"},
		{name: "assigned members", err: repository.ErrRoleInUse, status: http.StatusConflict, text: "another role"},
		{name: "concurrent deletion", err: sql.ErrNoRows, status: http.StatusNotFound, text: "no longer exists"},
		{
			name: "storage failure", err: errors.New("storage failed"),
			status: http.StatusInternalServerError, text: "Try again",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, _, _ := setupTest()
			h.identityRepo = &roleMutationRepository{
				role:      models.AccessRole{ID: "custom", Permissions: "gui_read", Revision: 3},
				deleteErr: tt.err,
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "role-editor")
			c.Set("permissions", models.AllPermissions())
			c.Params = gin.Params{{Key: "id", Value: "custom"}}
			c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/roles/custom", nil)
			h.DeleteRole(c)
			if w.Code != tt.status || !strings.Contains(w.Body.String(), tt.text) {
				t.Fatalf("status=%d body=%s, want %d containing %q", w.Code, w.Body, tt.status, tt.text)
			}
		})
	}
}

func TestAPIHandler_ChangeAdminRoleUI(t *testing.T) {
	for _, tt := range []struct {
		name     string
		username string
		override bool
		writeErr error
		status   int
	}{
		{name: "assign local role", username: "member", status: http.StatusOK},
		{name: "explicit Entra override", username: "member", override: true, status: http.StatusOK},
		{name: "recovery account protected", username: "admin", status: http.StatusForbidden},
		{
			name: "concurrent role change", username: "member", writeErr: repository.ErrIdentityConflict,
			status: http.StatusConflict,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			repo := &roleUIRepository{
				roleMutationRepository: roleMutationRepository{
					role: models.AccessRole{ID: "viewer", Permissions: "gui_read"},
				},
				writeErr: tt.writeErr,
			}
			h.identityRepo = repo
			if tt.username != "admin" {
				pg.On("GetAdmin", tt.username).Return(&models.AdminAccount{
					Username: tt.username, Permissions: "gui_read", AuthSource: "local",
				}, nil).Once()
			}
			body, err := json.Marshal(map[string]any{
				"username": tt.username, "role": "viewer", "entra_role_override": tt.override,
			})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "account-editor")
			c.Set("permissions", models.AllPermissions())
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/change_role", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			h.ChangeAdminRole(c)
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d: %s", w.Code, tt.status, w.Body)
			}
			if tt.username == "admin" {
				if repo.assigned != nil {
					t.Fatal("recovery role changed")
				}
			} else if repo.assigned == nil || repo.assigned.Username != "member" ||
				repo.assigned.Role != "viewer" || repo.assigned.EntraRoleOverride != tt.override || repo.actor != "account-editor" {
				t.Fatalf("incorrect role assignment or actor: %+v / %q", repo.assigned, repo.actor)
			}
			pg.AssertExpectations(t)
		})
	}
}
