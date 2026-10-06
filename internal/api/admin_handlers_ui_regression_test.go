package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/gin-gonic/gin"
)

func TestAPIHandler_CreateManagedLocalAccountUI(t *testing.T) {
	for _, tt := range []struct {
		name     string
		password string
		hashErr  error
		writeErr error
		status   int
	}{
		{name: "minimum password", password: strings.Repeat("a", 12), status: http.StatusOK},
		{name: "maximum password", password: strings.Repeat("a", 72), status: http.StatusOK},
		{name: "short password", password: strings.Repeat("a", 11), status: http.StatusBadRequest},
		{name: "long password", password: strings.Repeat("a", 73), status: http.StatusBadRequest},
		{
			name: "hashing failure", password: "test-only-password", hashErr: errors.New("private hash failure"),
			status: http.StatusInternalServerError,
		},
		{
			name: "duplicate account", password: "test-only-password", writeErr: repository.ErrIdentityConflict,
			status: http.StatusConflict,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _, auth, _ := setupTest()
			repo := &managedAccountTestRepository{err: tt.writeErr}
			h.identityRepo = repo
			validLength := len(tt.password) >= 12 && len(tt.password) <= 72
			if validLength {
				auth.On("HashPassword", tt.password).Return("test-only-hash", tt.hashErr).Once()
			}
			body, err := json.Marshal(map[string]string{
				"username": "  member  ", "password": tt.password, "auth_source": "local",
				"entra_upn": "must-not-persist@example.test",
			})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("username", "account-editor")
			c.Set("permissions", models.AllPermissions())
			c.Request = httptest.NewRequest(http.MethodPost, "/admin_management/create", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			h.CreateAdmin(c)
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d: %s", w.Code, tt.status, w.Body)
			}
			for _, secret := range []string{tt.password, "test-only-hash", "private hash failure"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Errorf("account response contains sensitive value %q", secret)
				}
			}
			if !validLength || tt.hashErr != nil {
				if repo.created != nil {
					t.Fatal("invalid account persisted")
				}
			} else {
				if repo.created == nil {
					t.Fatal("valid account did not reach repository")
				}
				account := *repo.created
				validAccount := account.Username == "member" && account.Role == "viewer" &&
					account.AuthSource == "local" && account.PasswordHash == "test-only-hash" && account.EntraUPN == ""
				if !validAccount {
					t.Fatalf("incorrect account fields: %+v", account)
				}
			}
			auth.AssertExpectations(t)
		})
	}
}

type logUIRepository struct {
	IdentityRepositoryProvider
	filter models.LogFilter
	err    error
}

func (r *logUIRepository) ListLogs(_ context.Context, filter models.LogFilter) ([]models.AuditLog, int, error) {
	r.filter = filter
	return []models.AuditLog{}, 125, r.err
}

func TestAPIHandler_LogExplorerUIFiltersAndPagination(t *testing.T) {
	for _, screen := range []struct {
		name     string
		path     string
		category string
		title    string
		action   string
	}{
		{
			name: "system", path: "/audit-logs", category: "system",
			title: "System audit logs", action: "CREATE_ROLE",
		},
		{
			name: "events", path: "/event-logs", category: "events",
			title: "Event logs", action: "BLOCK",
		},
	} {
		for _, page := range []struct {
			name   string
			value  string
			offset int
			label  string
		}{
			{name: "first", value: "1", offset: 0, label: "Page 1 of 3"},
			{name: "next", value: "2", offset: 50, label: "Page 2 of 3"},
			{name: "last", value: "3", offset: 100, label: "Page 3 of 3"},
			{name: "invalid", value: "invalid", offset: 0, label: "Page 1 of 3"},
			{name: "negative", value: "-1", offset: 0, label: "Page 1 of 3"},
			{name: "too large", value: "1000001", offset: 0, label: "Page 1 of 3"},
		} {
			t.Run(screen.name+"/"+page.name, func(t *testing.T) {
				h, _, _, _, _ := setupTest()
				repo := &logUIRepository{}
				h.identityRepo = repo
				query := url.Values{
					"page": {page.value}, "actor": {"operator@example.test"},
					"action": {screen.action}, "query": {"host & subnet"},
				}
				w := httptest.NewRecorder()
				c, _ := setupHTMLTest(w)
				c.Set("username", "viewer")
				c.Set("permissions", "gui_read,view_audit_logs,view_event_logs")
				c.Request = httptest.NewRequest(http.MethodGet, screen.path+"?"+query.Encode(), nil)
				if screen.category == "system" {
					h.AuditLogExplorer(c)
				} else {
					h.EventLogExplorer(c)
				}
				wantFilter := models.LogFilter{
					Category: screen.category, Actor: "operator@example.test", Action: screen.action,
					Query: "host & subnet", Limit: 50, Offset: page.offset,
				}
				if repo.filter != wantFilter {
					t.Fatalf("filter=%+v, want %+v", repo.filter, wantFilter)
				}
				if w.Code != http.StatusOK {
					t.Fatalf("status=%d: %s", w.Code, w.Body)
				}
				for _, text := range []string{
					"<h1>" + screen.title + "</h1>", `action="` + screen.path + `"`,
					page.label, `value="operator@example.test"`, `value="host &amp; subnet"`,
				} {
					if !strings.Contains(w.Body.String(), text) {
						t.Errorf("rendered log page missing %q", text)
					}
				}
				if page.offset == 50 {
					for _, text := range []string{
						screen.path + "?page=1", screen.path + "?page=3",
						"actor=operator%40example.test", "action=" + screen.action, "query=host%20%26%20subnet",
					} {
						if !strings.Contains(w.Body.String(), text) {
							t.Errorf("pagination does not preserve filter %q", text)
						}
					}
				}
			})
		}
	}
}

func TestAPIHandler_LogExplorerUIFailure(t *testing.T) {
	for _, category := range []string{"system", "events"} {
		t.Run(category, func(t *testing.T) {
			h, _, _, _, _ := setupTest()
			h.identityRepo = &logUIRepository{err: errors.New("private query failure")}
			w := httptest.NewRecorder()
			c, _ := setupHTMLTest(w)
			c.Set("username", "viewer")
			c.Set("permissions", "gui_read,view_audit_logs,view_event_logs")
			c.Request = httptest.NewRequest(http.MethodGet, "/logs", nil)
			if category == "system" {
				h.AuditLogExplorer(c)
			} else {
				h.EventLogExplorer(c)
			}
			if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private query failure") {
				t.Fatalf("unexpected error response: %d %s", w.Code, w.Body)
			}
		})
	}
}
