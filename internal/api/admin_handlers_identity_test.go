package api

import (
	"context"
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

type managedAccountTestRepository struct {
	IdentityRepositoryProvider
	created *models.AdminAccount
	err     error
}

func (r *managedAccountTestRepository) GetRole(_ context.Context, id string) (*models.AccessRole, error) {
	return &models.AccessRole{ID: id, Permissions: "gui_read"}, nil
}

func (r *managedAccountTestRepository) CreateManagedAdmin(_ context.Context, admin models.AdminAccount, _ string) error {
	r.created = &admin
	return r.err
}

func TestAPIHandlerCreateEntraAccount(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	const object = "22222222-2222-2222-2222-222222222222"
	for _, tc := range []struct {
		name     string
		request  map[string]string
		status   int
		username string
		prebound bool
		conflict bool
	}{
		{
			name:    "upn and role only",
			request: map[string]string{"auth_source": "entra", "entra_upn": "Person@example.test", "role": "viewer"},
			status:  http.StatusOK, username: "person@example.test",
		},
		{
			name:    "upn defines pending account name",
			request: map[string]string{"auth_source": "entra", "entra_upn": " Person@Example.test ", "username": "ignored"},
			status:  http.StatusOK, username: "person@example.test",
		},
		{
			name:    "missing upn",
			request: map[string]string{"auth_source": "entra", "username": "person@example.test"},
			status:  http.StatusBadRequest,
		},
		{
			name:    "display name is not a upn",
			request: map[string]string{"auth_source": "entra", "entra_upn": "Person <person@example.test>"},
			status:  http.StatusBadRequest,
		},
		{
			name:    "preserves explicit api prebinding",
			request: map[string]string{"auth_source": "entra", "username": "prebound", "entra_tenant_id": tenant, "entra_object_id": object},
			status:  http.StatusOK, username: "prebound", prebound: true,
		},
		{
			name:    "partial binding rejected",
			request: map[string]string{"auth_source": "entra", "username": "partial", "entra_upn": "person@example.test", "entra_tenant_id": tenant},
			status:  http.StatusBadRequest,
		},
		{
			name:    "foreign tenant rejected",
			request: map[string]string{"auth_source": "entra", "username": "foreign", "entra_tenant_id": object, "entra_object_id": object},
			status:  http.StatusBadRequest,
		},
		{
			name:    "duplicate pending upn is a conflict",
			request: map[string]string{"auth_source": "entra", "entra_upn": "person@example.test"},
			status:  http.StatusConflict, conflict: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _, _, _ := setupTest()
			repo := &managedAccountTestRepository{}
			if tc.conflict {
				repo.err = repository.ErrIdentityConflict
			}
			h.identityRepo = repo
			h.cfg.EntraTenantID = tenant
			body, err := json.Marshal(tc.request)
			require.NoError(t, err)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "admin")
			c.Set("permissions", models.AllPermissions())
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/create", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			h.CreateAdmin(c)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.status == http.StatusBadRequest {
				require.Nil(t, repo.created)
				return
			}
			if tc.status != http.StatusOK {
				return
			}
			require.NotNil(t, repo.created)
			require.Equal(t, tc.username, repo.created.Username)
			require.Equal(t, "entra", repo.created.AuthSource)
			require.Empty(t, repo.created.PasswordHash)
			if tc.prebound {
				require.Equal(t, tenant, *repo.created.EntraTenantID)
				require.Equal(t, object, *repo.created.EntraObjectID)
				return
			}
			require.Equal(t, tc.username, repo.created.EntraUPN)
			require.Nil(t, repo.created.EntraTenantID)
			require.Nil(t, repo.created.EntraObjectID)
		})
	}
}
