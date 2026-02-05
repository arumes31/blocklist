package api

import (
	"context"
	"html/template"
	"net/http/httptest"
	"strings"
	"time"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
)

func setupHTMLTest(w *httptest.ResponseRecorder) (*gin.Context, *gin.Engine) {
	c, r := gin.CreateTestContext(w)
	r.SetFuncMap(template.FuncMap{
		"lower":    strings.ToLower,
		"replace":  strings.ReplaceAll,
		"split":    strings.Split,
		"contains": strings.Contains,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
		"safeURL":  func(s string) template.URL { return template.URL(s) },
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
	})
	r.LoadHTMLGlob("../../cmd/server/templates/*")
	return c, r
}

// MockIPService implements IPServiceProvider
type MockIPService struct {
	mock.Mock
}

func (m *MockIPService) IsBlocked(ipStr string) bool {
	args := m.Called(ipStr)
	return args.Bool(0)
}

func (m *MockIPService) BlockIP(ctx context.Context, ip string, reason string, username string, actorIP string, persist bool, duration time.Duration) (*models.IPEntry, error) {
	args := m.Called(ctx, ip, reason, username, actorIP, persist, duration)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.IPEntry), args.Error(1)
}

func (m *MockIPService) UnblockIP(ctx context.Context, ip string, username string) error {
	args := m.Called(ctx, ip, username)
	return args.Error(0)
}

func (m *MockIPService) BulkBlock(ctx context.Context, ips []string, reason string, addedBy string, actorIP string, persist bool, ttl int) error {
	args := m.Called(ctx, ips, reason, addedBy, actorIP, persist, ttl)
	return args.Error(0)
}

func (m *MockIPService) BulkUnblock(ctx context.Context, ips []string, actor string) error {
	args := m.Called(ctx, ips, actor)
	return args.Error(0)
}

func (m *MockIPService) WhitelistIP(ctx context.Context, ip string, reason string, username string) error {
	args := m.Called(ctx, ip, reason, username)
	return args.Error(0)
}

func (m *MockIPService) RemoveWhitelist(ctx context.Context, ip string, username string) error {
	args := m.Called(ctx, ip, username)
	return args.Error(0)
}

func (m *MockIPService) GetIPDetails(ctx context.Context, ip string) (map[string]interface{}, error) {
	args := m.Called(ctx, ip)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockIPService) ListIPsPaginatedAdvanced(ctx context.Context, limit int, cursor string, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, string, int, error) {
	args := m.Called(ctx, limit, cursor, query, country, addedBy, from, to)
	return args.Get(0).([]map[string]interface{}), args.String(1), args.Int(2), args.Error(3)
}

func (m *MockIPService) ExportIPs(ctx context.Context, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, error) {
	args := m.Called(ctx, query, country, addedBy, from, to)
	return args.Get(0).([]map[string]interface{}), args.Error(1)
}

func (m *MockIPService) Stats(ctx context.Context) (hour int, day int, totalEver int, activeBlocks int, top []struct {
	Country string
	Count   int
}, topASN []struct {
	ASN    uint
	ASNOrg string
	Count  int
}, topReason []struct {
	Reason string
	Count  int
}, webhooksHour int, lastBlockTs int64, blocksMinute int, whitelistCount int, err error) {
	args := m.Called(ctx)
	// Manual casting for complex structs in return
	return args.Int(0), args.Int(1), args.Int(2), args.Int(3),
		args.Get(4).([]struct {
			Country string
			Count   int
		}),
		args.Get(5).([]struct {
			ASN    uint
			ASNOrg string
			Count  int
		}),
		args.Get(6).([]struct {
			Reason string
			Count  int
		}),
		args.Int(7), args.Get(8).(int64), args.Int(9), args.Int(10), args.Error(11)
}

func (m *MockIPService) GetGeoIP(ipStr string) *models.GeoData {
	args := m.Called(ipStr)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*models.GeoData)
}

func (m *MockIPService) IsValidIP(ipStr string) bool {
	args := m.Called(ipStr)
	return args.Bool(0)
}

func (m *MockIPService) CalculateThreatScore(ip string, reason string) int {
	args := m.Called(ip, reason)
	return args.Int(0)
}

// MockRedisRepo implements RedisRepositoryProvider
type MockRedisRepo struct {
	mock.Mock
}

func (m *MockRedisRepo) HGetAllRaw(hashKey string) (map[string]string, error) {
	args := m.Called(hashKey)
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m *MockRedisRepo) GetWhitelistedIPs() (map[string]models.WhitelistEntry, error) {
	args := m.Called()
	return args.Get(0).(map[string]models.WhitelistEntry), args.Error(1)
}

func (m *MockRedisRepo) GetBlockedIPs() (map[string]models.IPEntry, error) {
	args := m.Called()
	return args.Get(0).(map[string]models.IPEntry), args.Error(1)
}

func (m *MockRedisRepo) IndexWebhookHit(ts time.Time) error {
	args := m.Called(ts)
	return args.Error(0)
}

func (m *MockRedisRepo) ExecBlockAtomic(ip string, entry models.IPEntry, ts time.Time) error {
	args := m.Called(ip, entry, ts)
	return args.Error(0)
}

func (m *MockRedisRepo) ExecUnblockAtomic(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

func (m *MockRedisRepo) WhitelistIP(ip string, entry models.WhitelistEntry) error {
	args := m.Called(ip, entry)
	return args.Error(0)
}

func (m *MockRedisRepo) RemoveFromWhitelist(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

func (m *MockRedisRepo) GetIPEntry(ip string) (*models.IPEntry, error) {
	args := m.Called(ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.IPEntry), args.Error(1)
}

func (m *MockRedisRepo) GetCache(key string, target interface{}) error {
	args := m.Called(key, target)
	return args.Error(0)
}

func (m *MockRedisRepo) SetCache(key string, val interface{}, expiration time.Duration) error {
	args := m.Called(key, val, expiration)
	return args.Error(0)
}

// MockPostgresRepo implements PostgresRepositoryProvider
type MockPostgresRepo struct {
	mock.Mock
}

func (m *MockPostgresRepo) GetSavedViews(username string) ([]models.SavedView, error) {
	args := m.Called(username)
	return args.Get(0).([]models.SavedView), args.Error(1)
}

func (m *MockPostgresRepo) CreateSavedView(view models.SavedView) error {
	args := m.Called(view)
	return args.Error(0)
}

func (m *MockPostgresRepo) DeleteSavedView(id int, username string) error {
	args := m.Called(id, username)
	return args.Error(0)
}

func (m *MockPostgresRepo) GetAllAdmins() ([]models.AdminAccount, error) {
	args := m.Called()
	return args.Get(0).([]models.AdminAccount), args.Error(1)
}

func (m *MockPostgresRepo) GetAdmin(username string) (*models.AdminAccount, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AdminAccount), args.Error(1)
}

func (m *MockPostgresRepo) UpdateAdminPermissions(username, permissions string) error {
	args := m.Called(username, permissions)
	return args.Error(0)
}

func (m *MockPostgresRepo) DeleteAdmin(username string) error {
	args := m.Called(username)
	return args.Error(0)
}

func (m *MockPostgresRepo) LogAction(username, action, target, details string) error {
	args := m.Called(username, action, target, details)
	return args.Error(0)
}

func (m *MockPostgresRepo) UpdateAdminPassword(username, hash string) error {
	args := m.Called(username, hash)
	return args.Error(0)
}

func (m *MockPostgresRepo) UpdateAdminToken(username, token string) error {
	args := m.Called(username, token)
	return args.Error(0)
}

func (m *MockPostgresRepo) CreateOutboundWebhook(wh models.OutboundWebhook) error {
	args := m.Called(wh)
	return args.Error(0)
}

func (m *MockPostgresRepo) DeleteOutboundWebhook(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPostgresRepo) GetActiveWebhooks() ([]models.OutboundWebhook, error) {
	args := m.Called()
	return args.Get(0).([]models.OutboundWebhook), args.Error(1)
}

func (m *MockPostgresRepo) GetAuditLogs(limit int) ([]models.AuditLog, error) {
	args := m.Called(limit)
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockPostgresRepo) GetAuditLogsPaginated(limit int, offset int, actor string, action string, query string) ([]models.AuditLog, int, error) {
	args := m.Called(limit, offset, actor, action, query)
	return args.Get(0).([]models.AuditLog), args.Int(1), args.Error(2)
}

func (m *MockPostgresRepo) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	args := m.Called(hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIToken), args.Error(1)
}

func (m *MockPostgresRepo) UpdateTokenLastUsed(id int, ip string) error {
	args := m.Called(id, ip)
	return args.Error(0)
}

func (m *MockPostgresRepo) CreateAPIToken(token models.APIToken) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockPostgresRepo) GetAPITokens(username string) ([]models.APIToken, error) {
	args := m.Called(username)
	return args.Get(0).([]models.APIToken), args.Error(1)
}

func (m *MockPostgresRepo) GetAllAPITokens() ([]models.APIToken, error) {
	args := m.Called()
	return args.Get(0).([]models.APIToken), args.Error(1)
}

func (m *MockPostgresRepo) DeleteAPIToken(id int, username string) error {
	args := m.Called(id, username)
	return args.Error(0)
}

func (m *MockPostgresRepo) UpdateAPITokenPermissions(id int, username, permissions string) error {
	args := m.Called(id, username, permissions)
	return args.Error(0)
}

func (m *MockPostgresRepo) DeleteAPITokenByID(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPostgresRepo) GetPersistentCount() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockPostgresRepo) GetPersistentBlocks() (map[string]models.IPEntry, error) {
	args := m.Called()
	return args.Get(0).(map[string]models.IPEntry), args.Error(1)
}

func (m *MockPostgresRepo) GetIPHistory(ip string) ([]models.AuditLog, error) {
	args := m.Called(ip)
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockPostgresRepo) GetBlockTrend() ([]models.BlockTrend, error) {
	args := m.Called()
	return args.Get(0).([]models.BlockTrend), args.Error(1)
}

func (m *MockPostgresRepo) CreatePersistentBlock(ip string, entry models.IPEntry) error {
	args := m.Called(ip, entry)
	return args.Error(0)
}

func (m *MockPostgresRepo) DeletePersistentBlock(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

// MockAuthService implements AuthServiceProvider
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) CheckAuth(username, password, token string) bool {
	args := m.Called(username, password, token)
	return args.Bool(0)
}

func (m *MockAuthService) VerifyTOTP(username, token string) bool {
	args := m.Called(username, token)
	return args.Bool(0)
}

func (m *MockAuthService) VerifySudo(username, password string) bool {
	args := m.Called(username, password)
	return args.Bool(0)
}

func (m *MockAuthService) Login(username, password, code string) (string, error) {
	args := m.Called(username, password, code)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) Logout(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockAuthService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) CreateAdmin(username, password, role, permissions string) (*models.AdminAccount, error) {
	args := m.Called(username, password, role, permissions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AdminAccount), args.Error(1)
}

func (m *MockAuthService) CreateAPIToken(username, name, permissions string) (*models.APIToken, string, error) {
	args := m.Called(username, name, permissions)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*models.APIToken), args.String(1), args.Error(2)
}

func (m *MockAuthService) DeleteAPIToken(tokenID int, username string) error {
	args := m.Called(tokenID, username)
	return args.Error(0)
}

func (m *MockAuthService) UpdateAPITokenPermissions(tokenID int, permissions string, username string) error {
	args := m.Called(tokenID, permissions, username)
	return args.Error(0)
}

func (m *MockAuthService) RevokeAPIToken(tokenID int) error {
	args := m.Called(tokenID)
	return args.Error(0)
}
