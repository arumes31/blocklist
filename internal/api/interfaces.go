package api

import (
	"context"
	"time"

	"blocklist/internal/models"
)

// IPServiceProvider defines the interface for IP operations
type IPServiceProvider interface {
	IsBlocked(ipStr string) bool
	BlockIP(ctx context.Context, ip string, reason string, username string, actorIP string, persist bool, duration time.Duration) error
	UnblockIP(ctx context.Context, ip string, username string) error
	BulkBlock(ctx context.Context, ips []string, reason string, addedBy string, actorIP string, persist bool, ttl int) error
	BulkUnblock(ctx context.Context, ips []string, actor string) error
	WhitelistIP(ctx context.Context, ip string, reason string, username string) error
	RemoveWhitelist(ctx context.Context, ip string, username string) error
	GetIPDetails(ctx context.Context, ip string) (map[string]interface{}, error)
	ListIPsPaginatedAdvanced(ctx context.Context, limit int, cursor string, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, string, int, error)
	ExportIPs(ctx context.Context, query string, country string, addedBy string, from string, to string) ([]map[string]interface{}, error)
	Stats(ctx context.Context) (hour int, day int, totalEver int, activeBlocks int, top []struct {
		Country string
		Count   int
	}, topASN []struct {
		ASN    uint
		ASNOrg string
		Count  int
	}, topReason []struct {
		Reason string
		Count  int
	}, webhooksHour int, lastBlockTs int64, blocksMinute int, err error)
	GetGeoIP(ipStr string) *models.GeoData
	IsValidIP(ipStr string) bool
	CalculateThreatScore(ip string, reason string) int
}

// AuthServiceProvider defines the interface for Auth operations
type AuthServiceProvider interface {
	CheckAuth(username, password, token string) bool
	VerifyTOTP(username, token string) bool
	HashPassword(password string) (string, error)
	CreateAdmin(username, password, role, permissions string) (*models.AdminAccount, error)
}

// RedisRepositoryProvider defines the interface for Redis operations
type RedisRepositoryProvider interface {
	HGetAllRaw(hashKey string) (map[string]string, error)
	GetWhitelistedIPs() (map[string]models.WhitelistEntry, error)
	GetBlockedIPs() (map[string]models.IPEntry, error)
	IndexWebhookHit(ts time.Time) error
	ExecBlockAtomic(ip string, entry models.IPEntry, ts time.Time) error
	ExecUnblockAtomic(ip string) error
	WhitelistIP(ip string, entry models.WhitelistEntry) error
	RemoveFromWhitelist(ip string) error
	GetIPEntry(ip string) (*models.IPEntry, error)
	GetCache(key string, target interface{}) error
	SetCache(key string, val interface{}, expiration time.Duration) error
}

// PostgresRepositoryProvider defines the interface for Postgres operations
type PostgresRepositoryProvider interface {
	GetSavedViews(username string) ([]models.SavedView, error)
	CreateSavedView(view models.SavedView) error
	DeleteSavedView(id int, username string) error
	GetAllAdmins() ([]models.AdminAccount, error)
	GetAdmin(username string) (*models.AdminAccount, error)
	UpdateAdminPermissions(username, permissions string) error
	DeleteAdmin(username string) error
	LogAction(username, action, target, details string) error
	UpdateAdminPassword(username, hash string) error
	UpdateAdminToken(username, token string) error
	CreateOutboundWebhook(wh models.OutboundWebhook) error
	DeleteOutboundWebhook(id int) error
	GetActiveWebhooks() ([]models.OutboundWebhook, error)
	GetAuditLogs(limit int) ([]models.AuditLog, error)
	GetAuditLogsPaginated(limit int, offset int, actor string, action string, query string) ([]models.AuditLog, int, error)

	// API Token methods
	GetAPITokenByHash(hash string) (*models.APIToken, error)
	UpdateTokenLastUsed(id int, ip string) error
	CreateAPIToken(token models.APIToken) error
	GetAPITokens(username string) ([]models.APIToken, error)
	GetAllAPITokens() ([]models.APIToken, error)
	DeleteAPIToken(id int, username string) error
	UpdateAPITokenPermissions(id int, username, permissions string) error
	DeleteAPITokenByID(id int) error

	GetPersistentCount() (int64, error)
	GetPersistentBlocks() (map[string]models.IPEntry, error)
	GetIPHistory(ip string) ([]models.AuditLog, error)
	GetBlockTrend() ([]models.BlockTrend, error)
	CreatePersistentBlock(ip string, entry models.IPEntry) error
	DeletePersistentBlock(ip string) error
}
