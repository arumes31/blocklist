//go:build integration

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/service"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"golang.org/x/crypto/bcrypt"
)

// Exercise the real routes, authentication and storage with tokens created on
// schema 16, before managed roles existed. No developer DSN or credentials are read.
func TestAPIHandler_UpgradeTokenCompatibility(t *testing.T) {
	ctx := t.Context()
	pgContainer, err := tcpostgres.Run(
		ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("upgrade_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword(rand.Text()),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, pgContainer)
	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	migrations, err := migrate.New("file://../../cmd/server/migrations", dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		sourceErr, databaseErr := migrations.Close()
		require.NoError(t, errors.Join(sourceErr, databaseErr))
	})
	require.NoError(t, migrations.Migrate(16))
	pg, err := repository.NewPostgresRepository(dsn, dsn, 100)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pg.Close()) })
	password := rand.Text()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	expired := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	fixtures := []struct {
		name       string
		scopes     string
		allowedIPs string
		expiresAt  *string
	}{
		{name: "fortigate", scopes: "view_ips", allowedIPs: "127.0.0.1/32"},
		{name: "fail2ban", scopes: "view_ips,block_ips,unblock_ips"},
		{name: "graylog", scopes: "view_ips,block_ips,unblock_ips,whitelist_ips"},
		{name: "read-only", scopes: "view_ips"},
		{name: "wrong-ip", scopes: "view_ips", allowedIPs: "192.0.2.0/24"},
		{name: "expired", scopes: "view_ips", expiresAt: &expired},
		{name: "revoked", scopes: "view_ips"},
		{name: "deleted-owner", scopes: "view_ips"},
		{name: "downgraded", scopes: "view_ips,block_ips,unblock_ips"},
		{name: "empty-scope", scopes: ""},
	}
	tokens := make(map[string]string)
	stored := make(map[string]models.APIToken)
	ownerRights := "view_ips,block_ips,unblock_ips,whitelist_ips"
	for _, fixture := range fixtures {
		require.NoError(t, pg.CreateAdmin(models.AdminAccount{
			Username: fixture.name, PasswordHash: string(passwordHash), Token: "preserved-mfa",
			Role: "admin", Permissions: ownerRights,
		}))
		raw := rand.Text()
		hash := sha256.Sum256([]byte(raw))
		token := models.APIToken{
			TokenHash: hex.EncodeToString(hash[:]), Name: fixture.name, Username: fixture.name,
			Role: "admin", Permissions: fixture.scopes, AllowedIPs: fixture.allowedIPs, ExpiresAt: fixture.expiresAt,
		}
		require.NoError(t, pg.CreateAPIToken(token))
		before, err := pg.GetAPITokenByHash(token.TokenHash)
		require.NoError(t, err)
		tokens[fixture.name], stored[fixture.name] = raw, *before
	}
	require.NoError(t, pg.LogAction("fortigate", "BLOCK", "198.51.100.9", "pre-upgrade-event"))
	require.NoError(t, pg.LogAction("fortigate", "CHANGE_PASSWORD", "fortigate", "pre-upgrade-audit"))
	require.NoError(t, pg.CreateSavedView(models.SavedView{
		Username: "fortigate", Name: "preserved-view", Filters: `{"query":"legacy"}`,
	}))
	require.NoError(t, pg.CreatePersistentBlock("198.51.100.9", models.IPEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Reason: "pre-upgrade", AddedBy: "fortigate",
	}))
	require.NoError(t, migrations.Up())
	require.ErrorIs(t, migrations.Up(), migrate.ErrNoChange, "migration must be restart-safe")
	for name, before := range stored {
		after, err := pg.GetAPITokenByHash(before.TokenHash)
		require.NoError(t, err)
		require.Equal(t, before, *after, "upgrade must preserve every token column: %s", name)
		owner, err := pg.GetAdmin(name)
		require.NoError(t, err)
		require.Equal(t, string(passwordHash), owner.PasswordHash)
		require.Equal(t, "preserved-mfa", owner.Token)
		require.Equal(t, ownerRights, owner.Permissions)
		require.Nil(t, owner.RoleID)
	}
	views, err := pg.GetSavedViews("fortigate")
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.JSONEq(t, `{"query":"legacy"}`, views[0].Filters)
	blocks, err := pg.GetPersistentBlocks()
	require.NoError(t, err)
	require.Equal(t, "pre-upgrade", blocks["198.51.100.9"].Reason)
	for _, category := range []string{"system", "events"} {
		logs, total, err := pg.ListLogs(ctx, models.LogFilter{Category: category, Query: "pre-upgrade", Limit: 10})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Len(t, logs, 1)
	}

	redisContainer, err := tcredis.Run(ctx, "redis:8.10.1-alpine")
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, redisContainer)
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	port, err := redisContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	portNumber, err := strconv.Atoi(port.Port())
	require.NoError(t, err)
	rRepo := repository.NewRedisRepository(host, portNumber, "", 0)
	t.Cleanup(func() { require.NoError(t, rRepo.Close()) })
	require.NoError(t, rRepo.WhitelistIP("203.0.113.7", models.WhitelistEntry{Reason: "legacy-allow"}))
	cfg := &config.Config{GUIAdmin: "recovery-not-an-integration-owner"}
	ipService := service.NewIPService(cfg, rRepo, pg)
	pass := func(c *gin.Context) { c.Next() }
	h := NewAPIHandler(&HandlerOptions{
		Config: cfg, PgRepo: pg, RedisRepo: rRepo, IPService: ipService,
		AuthService: service.NewAuthService(pg, rRepo),
		MainLimiter: pass, LoginLimiter: pass, WebhookLimiter: pass,
	})
	router := gin.New()
	require.NoError(t, router.SetTrustedProxies(nil))
	router.Use(sessions.Sessions("upgrade_session", cookie.NewStore([]byte(rand.Text()))))
	h.RegisterRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 10 * time.Second

	request := func(t *testing.T, method, path, token, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		// Forged forwarding headers must not bypass a source-IP restriction.
		req.Header.Set("X-Forwarded-For", "192.0.2.7")
		response, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		return response.StatusCode, string(data)
	}
	t.Run("Fortigate raw and JSON whitelist contracts", func(t *testing.T) {
		status, body := request(t, http.MethodGet, "/api/v1/whitelists-raw", tokens["fortigate"], "")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "203.0.113.7", strings.TrimSpace(body))
		status, body = request(t, http.MethodGet, "/api/v1/whitelists", tokens["fortigate"], "")
		require.Equal(t, http.StatusOK, status)
		var entries []struct {
			IP        string                `json:"ip"`
			Data      models.WhitelistEntry `json:"data"`
			ExpiresIn string                `json:"expires_in"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &entries))
		require.Len(t, entries, 1)
		require.Equal(t, "203.0.113.7", entries[0].IP)
		require.Equal(t, "legacy-allow", entries[0].Data.Reason)
		require.Equal(t, "NEVER", entries[0].ExpiresIn)
		used, err := pg.GetAPITokenByHash(stored["fortigate"].TokenHash)
		require.NoError(t, err)
		require.NotNil(t, used.LastUsed)
		require.Equal(t, "127.0.0.1", used.LastUsedIP)
	})
	t.Run("Fortigate legacy Basic Auth remains whitelist-only", func(t *testing.T) {
		for _, path := range []string{"/api/v1/whitelists-raw", "/api/v1/whitelists", "/api/v1/ips_list"} {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
			require.NoError(t, err)
			req.SetBasicAuth("fortigate", password)
			resp, err := client.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			want := http.StatusOK
			if path == "/api/v1/ips_list" {
				want = http.StatusUnauthorized
			}
			require.Equal(t, want, resp.StatusCode, path)
		}
	})
	for index, owner := range []string{"fail2ban", "graylog"} {
		t.Run(owner+" webhook compatibility", func(t *testing.T) {
			ip := "198.51.100." + strconv.Itoa(20+index)
			for _, action := range []string{"ban", "unban"} {
				body := `{"ip":"` + ip + `","act":"` + action + `","reason":"compatibility","ttl":120}`
				status, response := request(t, http.MethodPost, "/api/v1/webhook", tokens[owner], body)
				require.Equal(t, http.StatusOK, status, response)
				want := "IP banned"
				if action == "unban" {
					want = "IP unbanned"
				}
				require.JSONEq(t, `{"status":"`+want+`","ip":"`+ip+`"}`, response)
				blocked, err := rRepo.GetBlockedIPs()
				require.NoError(t, err)
				_, exists := blocked[ip]
				require.Equal(t, action == "ban", exists)
			}
		})
	}
	t.Run("revocation and scope restrictions", func(t *testing.T) {
		require.NoError(t, pg.DeleteAPITokenByID(stored["revoked"].ID))
		require.NoError(t, pg.DeleteAdmin("deleted-owner"))
		for _, tc := range []struct {
			name, method, path, body string
			status                   int
		}{
			{name: "read-only", method: "POST", path: "/api/v1/webhook", body: `{"ip":"198.51.100.30","act":"ban"}`, status: 403},
			{name: "wrong-ip", method: "GET", path: "/api/v1/whitelists", status: 403},
			{name: "expired", method: "GET", path: "/api/v1/whitelists", status: 401},
			{name: "revoked", method: "GET", path: "/api/v1/whitelists", status: 401},
			{name: "deleted-owner", method: "GET", path: "/api/v1/whitelists", status: 401},
			{name: "empty-scope", method: "GET", path: "/api/v1/whitelists", status: 403},
		} {
			t.Run(tc.name, func(t *testing.T) {
				status, body := request(t, tc.method, tc.path, tokens[tc.name], tc.body)
				require.Equal(t, tc.status, status, body)
			})
		}
	})
	t.Run("existing token follows owner role downgrade immediately", func(t *testing.T) {
		require.NoError(t, pg.AssignAdminRole(ctx, models.AdminAccount{Username: "downgraded", Role: "editor"}, "test"))
		body := `{"ip":"198.51.100.40","act":"ban"}`
		status, response := request(t, http.MethodPost, "/api/v1/webhook", tokens["downgraded"], body)
		require.Equal(t, http.StatusOK, status, response)
		require.NoError(t, pg.AssignAdminRole(ctx, models.AdminAccount{Username: "downgraded", Role: "viewer"}, "test"))
		status, response = request(t, http.MethodPost, "/api/v1/webhook", tokens["downgraded"], body)
		require.Equal(t, http.StatusForbidden, status, response)
		status, _ = request(t, http.MethodGet, "/api/v1/whitelists", tokens["downgraded"], "")
		require.Equal(t, http.StatusOK, status)
		token, err := pg.GetAPITokenByHash(stored["downgraded"].TokenHash)
		require.NoError(t, err)
		require.Equal(t, stored["downgraded"].Permissions, token.Permissions, "owner rights bound the unchanged token scope")
	})
}
