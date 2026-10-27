package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/service"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	displayEntraKey  = "entra:36c0ac06-6d8c-45b3-8a7f-9f7bb48e20f5:26854b10-125c-4d3b-9085-95a8b753f152"
	displayEntraName = "editor@example.test"
)

type staticAccountLabels map[string]string

func (s staticAccountLabels) AccountLabels(context.Context) (map[string]string, error) {
	return s, nil
}

func setupAccountLabelTest() (*APIHandler, *MockRedisRepo, *MockPostgresRepo, *MockIPService) {
	h, rRepo, pgRepo, _, ipService := setupTest()
	h.accountLabels = service.NewAccountLabels(staticAccountLabels{displayEntraKey: displayEntraName})
	return h, rRepo, pgRepo, ipService
}

func requireSignInNameOnly(t *testing.T, body string, want ...string) {
	t.Helper()
	require.NotContains(t, body, "entra:", "account keys belong only on account management")
	for _, text := range want {
		require.Contains(t, body, text)
	}
}

type labeledLogRepository struct {
	IdentityRepositoryProvider
	logs []models.AuditLog
}

func (r *labeledLogRepository) ListLogs(context.Context, models.LogFilter) ([]models.AuditLog, int, error) {
	return r.logs, len(r.logs), nil
}

func TestLogExplorerShowsEntraSignInNames(t *testing.T) {
	h, _, _, _ := setupAccountLabelTest()
	h.identityRepo = &labeledLogRepository{logs: []models.AuditLog{
		{Actor: displayEntraKey, Action: "ENTRA_LOGIN_SUCCESS", Target: "REDACTED", Reason: "App role: editor"},
		{Actor: "admin", Action: "ASSIGN_ROLE", Target: displayEntraKey, Reason: "Role: moderator"},
		{Actor: "Webhook (" + displayEntraKey + ":203.0.113.7)", Action: "UNBLOCK", Target: "198.51.100.1"},
	}}
	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Set("username", "admin")
	c.Set("permissions", "gui_read,view_audit_logs")
	c.Request = httptest.NewRequest(http.MethodGet, "/audit-logs", nil)

	h.AuditLogExplorer(c)

	require.Equal(t, http.StatusOK, w.Code)
	requireSignInNameOnly(t, w.Body.String(),
		"<td>"+displayEntraName+"</td>",
		"<code>"+displayEntraName+"</code>",
		"Webhook ("+displayEntraName+":203.0.113.7)",
		`placeholder="Actor (email or username)"`,
	)
}

func TestWhitelistAndExclusionsShowEntraSignInNames(t *testing.T) {
	h, rRepo, pgRepo, _ := setupAccountLabelTest()
	rRepo.On("GetWhitelistedIPs").Return(map[string]models.WhitelistEntry{
		"62.68.209.114": {AddedBy: displayEntraKey, Reason: "FGT-WAN"},
		"198.51.100.5":  {AddedBy: "WebhookWhitelist (" + displayEntraKey + ":203.0.113.7)", Reason: "self"},
	}, nil)
	rRepo.On("GetExcludedEntries").Return(map[string]models.ExcludedEntry{
		"api.example.com": {Value: "api.example.com", Type: "fqdn", AddedBy: displayEntraKey},
	}, nil)
	pgRepo.On("GetAllExternalSources").Return([]models.ExternalSource{}, nil)

	for _, tc := range []struct {
		name    string
		path    string
		handler gin.HandlerFunc
		html    bool
		want    []string
	}{
		{name: "whitelist page", path: "/whitelist", handler: h.Whitelist, html: true, want: []string{
			"<td>" + displayEntraName + "</td>", "WebhookWhitelist (" + displayEntraName + ":203.0.113.7)",
		}},
		{name: "whitelist json", path: "/api/v1/whitelists", handler: h.JSONWhitelists, want: []string{
			`"added_by":"` + displayEntraName + `"`,
		}},
		{name: "exclusions page", path: "/excluded", handler: h.Excluded, html: true, want: []string{
			"<td>" + displayEntraName + "</td>",
		}},
		{name: "exclusions json", path: "/api/v1/excluded", handler: h.JSONExcluded, want: []string{
			`"added_by":"` + displayEntraName + `"`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			if tc.html {
				c, _ = setupHTMLTest(w)
			}
			c.Set("username", "admin")
			c.Set("permissions", "all")
			c.Request = httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.handler(c)
			require.Equal(t, http.StatusOK, w.Code)
			requireSignInNameOnly(t, w.Body.String(), tc.want...)
		})
	}
}

func TestBlockedRecordsShowEntraSignInNames(t *testing.T) {
	blocked := func() map[string]models.IPEntry {
		return map[string]models.IPEntry{
			"198.51.100.1": {AddedBy: displayEntraKey + " (203.0.113.7)", Reason: "scanner"},
		}
	}
	t.Run("dashboard table", func(t *testing.T) {
		h, rRepo, _, _ := setupAccountLabelTest()
		rRepo.On("GetBlockedIPs").Return(blocked(), nil)
		rRepo.On("GetCache", "persistent_ips_cache", mock.Anything).Return(errors.New("cache miss"))
		h.pgRepo.(*MockPostgresRepo).On("GetPersistentBlocks").Return(map[string]models.IPEntry{}, nil)
		rRepo.On("SetCache", "persistent_ips_cache", mock.Anything, mock.Anything).Return(nil)
		w := httptest.NewRecorder()
		c, _ := setupHTMLTest(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/dashboard/table", nil)
		h.DashboardTable(c)
		require.Equal(t, http.StatusOK, w.Code)
		requireSignInNameOnly(t, w.Body.String(), displayEntraName+" (203.0.113.7)")
	})
	t.Run("ips list json", func(t *testing.T) {
		h, rRepo, _, _ := setupAccountLabelTest()
		rRepo.On("GetBlockedIPs").Return(blocked(), nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ips_list", nil)
		h.JSONIPs(c)
		require.Equal(t, http.StatusOK, w.Code)
		requireSignInNameOnly(t, w.Body.String(), `"added_by":"`+displayEntraName+` (203.0.113.7)"`)
	})
}

func TestWorkspaceTokensShowEntraOwnerSignInName(t *testing.T) {
	h, _, pgRepo, _ := setupAccountLabelTest()
	pgRepo.On("GetAllAPITokens").Return([]models.APIToken{{ID: 7, Name: "firewall", Username: displayEntraKey}}, nil)
	pgRepo.On("GetAPITokens", "admin").Return([]models.APIToken{}, nil)
	pgRepo.On("GetActiveWebhooks").Return([]models.OutboundWebhook{}, nil)
	w := httptest.NewRecorder()
	c, _ := setupHTMLTest(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/settings", nil)
	c.Set("username", "admin")
	c.Set("permissions", "gui_read,view_settings,manage_global_tokens")

	h.Settings(c)

	require.Equal(t, http.StatusOK, w.Code)
	requireSignInNameOnly(t, w.Body.String(), `<td style="font-weight: 600;">`+displayEntraName+`</td>`)
}

func TestLiveBlockEventShowsEntraSignInName(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	subscription := rdb.Subscribe(t.Context(), "blocklist_events")
	t.Cleanup(func() { _ = subscription.Close() })
	_, err := subscription.Receive(t.Context())
	require.NoError(t, err)

	h, _, _, ipService := setupAccountLabelTest()
	h.hub = NewHub(rdb)
	stored := &models.IPEntry{AddedBy: displayEntraKey + " (203.0.113.7)", Reason: "scanner"}
	ipService.On("BlockIP", mock.Anything, "198.51.100.1", "scanner", displayEntraKey, mock.Anything, false, time.Duration(0)).Return(stored, nil)
	ipService.On("GetGeoIP", mock.Anything).Return(&models.GeoData{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("username", displayEntraKey)
	c.Request = httptest.NewRequest(http.MethodPost, "/block", strings.NewReader(`{"ip":"198.51.100.1","reason":"scanner"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	h.BlockIP(c)

	require.Equal(t, http.StatusOK, w.Code)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	message, err := subscription.ReceiveMessage(ctx)
	require.NoError(t, err)
	var event struct {
		Data struct {
			Data models.IPEntry `json:"data"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(message.Payload), &event))
	require.Equal(t, displayEntraName+" (203.0.113.7)", event.Data.Data.AddedBy)
	require.Equal(t, displayEntraKey+" (203.0.113.7)", stored.AddedBy, "the stored record keeps the account key")
}
