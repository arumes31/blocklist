package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type roleMutationRepository struct {
	IdentityRepositoryProvider
	role           models.AccessRole
	saved          bool
	deleted        bool
	readErr        error
	deleteErr      error
	deleteRevision int
}

func (r *roleMutationRepository) GetRole(context.Context, string) (*models.AccessRole, error) {
	if r.readErr != nil {
		return nil, r.readErr
	}
	role := r.role
	return &role, nil
}

func (r *roleMutationRepository) DeleteRole(_ context.Context, _, _ string, revision int) error {
	r.deleteRevision = revision
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.deleted = true
	return nil
}

func (r *roleMutationRepository) SaveRole(context.Context, models.AccessRole, string) error {
	r.saved = true
	return nil
}

func TestAPIHandler_SaveRoleExistingPermissions(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		storedPerms string
		submitted   string
		revision    int
		want        int
	}{
		{
			name: "create permitted role", method: http.MethodPost,
			submitted: "gui_read", want: http.StatusOK,
		},
		{
			name: "reject granting extra permission", method: http.MethodPost,
			submitted: "manage_admins", want: http.StatusForbidden,
		},
		{
			name: "update permitted role", method: http.MethodPut,
			storedPerms: "gui_read", submitted: "gui_read", revision: 2, want: http.StatusOK,
		},
		{
			name: "reject stripping privileged role", method: http.MethodPut,
			storedPerms: "gui_read,manage_admins", submitted: "gui_read", revision: 2, want: http.StatusForbidden,
		},
		{
			name: "reject stale revision", method: http.MethodPut,
			storedPerms: "gui_read", submitted: "gui_read", revision: 1, want: http.StatusConflict,
		},
		{
			name: "reject guessed future revision", method: http.MethodPut,
			storedPerms: "gui_read", submitted: "gui_read", revision: 3, want: http.StatusConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, _, _ := setupTest()
			repo := &roleMutationRepository{
				role: models.AccessRole{ID: "target", Permissions: tt.storedPerms, Revision: 2},
			}
			h.identityRepo = repo
			body, err := json.Marshal(models.AccessRole{
				ID: "target", Name: "Target", Permissions: tt.submitted, Revision: tt.revision,
			})
			require.NoError(t, err)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "limited-manager")
			c.Set("permissions", "gui_read,manage_roles")
			c.Params = gin.Params{{Key: "id", Value: "target"}}
			c.Request = httptest.NewRequest(tt.method, "/api/v1/roles/target", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			h.SaveRole(c)
			require.Equal(
				t,
				tt.want,
				w.Code,
				w.Body.String(),
			)
			require.Equal(t, tt.want == http.StatusOK, repo.saved)
		})
	}
}

func TestAPIHandler_DeleteRoleExistingPermissions(t *testing.T) {
	tests := []struct {
		name        string
		storedPerms string
		actorPerms  string
		readErr     error
		deleteErr   error
		want        int
	}{
		{name: "delete permitted role", storedPerms: "gui_read", want: http.StatusOK},
		{name: "reject privileged role", storedPerms: "gui_read,manage_admins", want: http.StatusForbidden},
		{
			name: "editor may manage privileged role", storedPerms: models.AllPermissions(),
			actorPerms: models.AllPermissions(), want: http.StatusOK,
		},
		{name: "missing role", readErr: sql.ErrNoRows, want: http.StatusNotFound},
		{
			name: "role changed after authorization", storedPerms: "gui_read",
			deleteErr: repository.ErrIdentityConflict, want: http.StatusConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, _, _ := setupTest()
			repo := &roleMutationRepository{
				role:    models.AccessRole{ID: "target", Permissions: tt.storedPerms, Revision: 7},
				readErr: tt.readErr, deleteErr: tt.deleteErr,
			}
			h.identityRepo = repo
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "limited-manager")
			permissions := "gui_read,manage_roles"
			if tt.actorPerms != "" {
				permissions = tt.actorPerms
			}
			c.Set("permissions", permissions)
			c.Params = gin.Params{{Key: "id", Value: "target"}}
			c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/roles/target", nil)
			h.DeleteRole(c)
			require.Equal(
				t,
				tt.want,
				w.Code,
				w.Body.String(),
			)
			require.Equal(t, tt.want == http.StatusOK, repo.deleted)
			if tt.want == http.StatusOK || tt.deleteErr != nil {
				require.Equal(t, 7, repo.deleteRevision, "delete must bind to the authorized role revision")
			}
		})
	}
}
