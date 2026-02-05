package repository

import (
	"blocklist/internal/models"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

type PostgresRepository struct {
	db     *sqlx.DB
	readDb *sqlx.DB
}

func NewPostgresRepository(url string, readUrl string) (*PostgresRepository, error) {
	db, err := sqlx.Connect("pgx", url)
	if err != nil {
		return nil, err
	}

	// Configure connection pooling to handle high concurrency
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	readDb := db
	if readUrl != "" && readUrl != url {
		rdb, err := sqlx.Connect("pgx", readUrl)
		if err == nil {
			rdb.SetMaxOpenConns(25)
			rdb.SetMaxIdleConns(25)
			rdb.SetConnMaxLifetime(5 * time.Minute)
			readDb = rdb
		}
	}

	return &PostgresRepository{db: db, readDb: readDb}, nil
}

func (p *PostgresRepository) GetAdmin(username string) (*models.AdminAccount, error) {
	var admin models.AdminAccount
	err := p.readDb.Get(&admin, "SELECT username, password_hash, token, role, permissions, session_version FROM admins WHERE username = $1", username)
	if err != nil {
		return nil, err
	}
	return &admin, nil
}

func (p *PostgresRepository) EnsurePartitions(retentionMonths int) error {
	// 1. Create partitions for current month and next 2 months
	now := time.Now().UTC()
	for i := 0; i <= 2; i++ {
		target := now.AddDate(0, i, 0)
		year := target.Year()
		month := int(target.Month())

		// Start of month
		start := time.Date(year, target.Month(), 1, 0, 0, 0, 0, time.UTC)
		// Start of next month
		end := start.AddDate(0, 1, 0)

		partitionName := fmt.Sprintf("y%dm%02d", year, month)

		tables := []string{"audit_logs", "webhook_logs"}
		for _, table := range tables {
			fullName := fmt.Sprintf("%s_%s", table, partitionName)
			query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
				fullName, table, start.Format("2006-01-01"), end.Format("2006-01-01"))
			_, err := p.db.Exec(query)
			if err != nil {
				return err
			}
		}
	}

	// 2. Drop partitions older than retentionMonths
	if retentionMonths > 0 {
		cutoff := now.AddDate(0, -retentionMonths, 0)
		// We iterate back a few more months to be sure we catch old ones if the job didn't run
		for i := 1; i <= 12; i++ {
			target := cutoff.AddDate(0, -i, 0)
			year := target.Year()
			month := int(target.Month())
			partitionName := fmt.Sprintf("y%dm%02d", year, month)

			tables := []string{"audit_logs", "webhook_logs"}
			for _, table := range tables {
				fullName := fmt.Sprintf("%s_%s", table, partitionName)
				// Check if partition exists before trying to drop (optional but cleaner)
				// For Postgres, we can just use DROP TABLE IF EXISTS
				query := fmt.Sprintf("DROP TABLE IF EXISTS %s", fullName)
				_, err := p.db.Exec(query)
				if err != nil {
					// Log error but continue
					fmt.Printf("Error dropping partition %s: %v\n", fullName, err)
				}
			}
		}
	}

	return nil
}

func (p *PostgresRepository) CreateAdmin(admin models.AdminAccount) error {
	if admin.Role == "" {
		admin.Role = "operator"
	}
	if admin.Permissions == "" {
		admin.Permissions = "gui_read"
	}
	if admin.SessionVersion == 0 {
		admin.SessionVersion = 1
	}
	_, err := p.db.NamedExec("INSERT INTO admins (username, password_hash, token, role, permissions, session_version) VALUES (:username, :password_hash, :token, :role, :permissions, :session_version)", admin)
	return err
}

func (p *PostgresRepository) UpdateAdminPassword(username, hash string) error {
	_, err := p.db.Exec("UPDATE admins SET password_hash = $1, session_version = session_version + 1 WHERE username = $2", hash, username)
	return err
}

func (p *PostgresRepository) UpdateAdminToken(username, token string) error {
	_, err := p.db.Exec("UPDATE admins SET token = $1, session_version = session_version + 1 WHERE username = $2", token, username)
	return err
}

func (p *PostgresRepository) UpdateAdminPermissions(username, permissions string) error {
	_, err := p.db.Exec("UPDATE admins SET permissions = $1, session_version = session_version + 1 WHERE username = $2", permissions, username)
	return err
}

func (p *PostgresRepository) IncrementSessionVersion(username string) error {
	_, err := p.db.Exec("UPDATE admins SET session_version = session_version + 1 WHERE username = $1", username)
	return err
}

func (p *PostgresRepository) DeleteAdmin(username string) error {
	_, err := p.db.Exec("DELETE FROM admins WHERE username = $1", username)
	return err
}

func (p *PostgresRepository) GetAllAdmins() ([]models.AdminAccount, error) {
	var admins []models.AdminAccount
	err := p.readDb.Select(&admins, "SELECT username, password_hash, token, role, permissions, session_version FROM admins")
	return admins, err
}

func (p *PostgresRepository) CreateAPIToken(token models.APIToken) error {
	_, err := p.db.NamedExec("INSERT INTO api_tokens (token_hash, name, username, role, permissions, allowed_ips, expires_at) VALUES (:token_hash, :name, :username, :role, :permissions, :allowed_ips, :expires_at)", token)
	return err
}

// GetAPITokenByHash lookups a token by its SHA256 hash
func (p *PostgresRepository) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	var token models.APIToken
	err := p.readDb.Get(&token, "SELECT id, token_hash, name, username, role, permissions, allowed_ips, created_at, expires_at, last_used, last_used_ip FROM api_tokens WHERE token_hash = $1", hash)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (p *PostgresRepository) GetAPITokens(username string) ([]models.APIToken, error) {
	var tokens []models.APIToken
	err := p.readDb.Select(&tokens, "SELECT id, name, username, role, permissions, allowed_ips, created_at, expires_at, last_used, last_used_ip FROM api_tokens WHERE username = $1 ORDER BY created_at DESC", username)
	return tokens, err
}

func (p *PostgresRepository) GetAllAPITokens() ([]models.APIToken, error) {
	var tokens []models.APIToken
	err := p.readDb.Select(&tokens, "SELECT id, name, username, role, permissions, allowed_ips, created_at, expires_at, last_used, last_used_ip FROM api_tokens ORDER BY created_at DESC")
	return tokens, err
}

func (p *PostgresRepository) DeleteAPIToken(id int, username string) error {
	_, err := p.db.Exec("DELETE FROM api_tokens WHERE id = $1 AND username = $2", id, username)
	return err
}

func (p *PostgresRepository) DeleteAPITokenByID(id int) error {
	_, err := p.db.Exec("DELETE FROM api_tokens WHERE id = $1", id)
	return err
}

func (p *PostgresRepository) UpdateAPITokenPermissions(id int, username, permissions string) error {
	_, err := p.db.Exec("UPDATE api_tokens SET permissions = $1 WHERE id = $2 AND username = $3", permissions, id, username)
	return err
}

func (p *PostgresRepository) UpdateTokenLastUsed(id int, ip string) error {
	_, err := p.db.Exec("UPDATE api_tokens SET last_used = NOW(), last_used_ip = $1 WHERE id = $2", ip, id)
	return err
}

func (p *PostgresRepository) CreateSavedView(view models.SavedView) error {
	_, err := p.db.NamedExec("INSERT INTO saved_views (username, name, filters) VALUES (:username, :name, :filters)", view)
	return err
}

func (p *PostgresRepository) GetSavedViews(username string) ([]models.SavedView, error) {
	var views []models.SavedView
	err := p.readDb.Select(&views, "SELECT id, username, name, filters, created_at FROM saved_views WHERE username = $1 ORDER BY created_at DESC", username)
	return views, err
}

func (p *PostgresRepository) DeleteSavedView(id int, username string) error {
	_, err := p.db.Exec("DELETE FROM saved_views WHERE id = $1 AND username = $2", id, username)
	return err
}

func (p *PostgresRepository) GetActiveWebhooks() ([]models.OutboundWebhook, error) {
	var webhooks []models.OutboundWebhook
	err := p.readDb.Select(&webhooks, "SELECT id, url, events, secret, geo_filter, active, created_at FROM outbound_webhooks WHERE active = TRUE")
	return webhooks, err
}

func (p *PostgresRepository) LogWebhookDelivery(logEntry models.WebhookLog) error {
	_, err := p.db.NamedExec("INSERT INTO webhook_logs (webhook_id, event, payload, status_code, response_body, error, attempt) VALUES (:webhook_id, :event, :payload, :status_code, :response_body, :error, :attempt)", logEntry)
	return err
}

func (p *PostgresRepository) CreateOutboundWebhook(wh models.OutboundWebhook) error {
	_, err := p.db.NamedExec("INSERT INTO outbound_webhooks (url, events, secret, geo_filter, active) VALUES (:url, :events, :secret, :geo_filter, :active)", wh)
	return err
}

func (p *PostgresRepository) DeleteOutboundWebhook(id int) error {
	_, err := p.db.Exec("DELETE FROM outbound_webhooks WHERE id = $1", id)
	return err
}

func (p *PostgresRepository) CreatePersistentBlock(ip string, entry models.IPEntry) error {
	geoJSON, _ := json.Marshal(entry.Geolocation)
	_, err := p.db.Exec("INSERT INTO persistent_blocks (ip, timestamp, reason, added_by, geo_json) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ip) DO UPDATE SET timestamp = $2, reason = $3, added_by = $4, geo_json = $5",
		ip, entry.Timestamp, entry.Reason, entry.AddedBy, geoJSON)
	return err
}

func (p *PostgresRepository) DeletePersistentBlock(ip string) error {
	_, err := p.db.Exec("DELETE FROM persistent_blocks WHERE ip = $1", ip)
	return err
}

func (p *PostgresRepository) GetPersistentBlocks() (map[string]models.IPEntry, error) {
	var results []struct {
		IP        string `db:"ip"`
		Timestamp string `db:"timestamp"`
		Reason    string `db:"reason"`
		AddedBy   string `db:"added_by"`
		GeoJSON   []byte `db:"geo_json"`
	}
	err := p.readDb.Select(&results, "SELECT ip, timestamp, reason, added_by, geo_json FROM persistent_blocks")
	if err != nil {
		return nil, err
	}

	ips := make(map[string]models.IPEntry)
	for _, r := range results {
		var geo models.GeoData
		if err := json.Unmarshal(r.GeoJSON, &geo); err != nil {
			continue
		}
		ips[r.IP] = models.IPEntry{
			Timestamp:   r.Timestamp,
			Geolocation: &geo,
			Reason:      r.Reason,
			AddedBy:     r.AddedBy,
		}
	}
	return ips, nil
}

func (p *PostgresRepository) GetPersistentCount() (int64, error) {
	var count int64
	err := p.readDb.Get(&count, "SELECT COUNT(*) FROM persistent_blocks")
	return count, err
}

func (p *PostgresRepository) LogAction(actor, action, target, reason string) error {
	_, err := p.db.Exec("INSERT INTO audit_logs (actor, action, target, reason) VALUES ($1, $2, $3, $4)", actor, action, target, reason)
	return err
}

func (p *PostgresRepository) GetAuditLogs(limit int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := p.readDb.Select(&logs, "SELECT id, timestamp, actor, action, target, reason FROM audit_logs ORDER BY timestamp DESC LIMIT $1", limit)
	return logs, err
}

func (p *PostgresRepository) GetAuditLogsPaginated(limit, offset int, actor, action, query string) ([]models.AuditLog, int, error) {
	var logs []models.AuditLog
	var total int

	baseQuery := "SELECT id, timestamp, actor, action, target, reason FROM audit_logs WHERE 1=1"
	params := []interface{}{}
	paramIdx := 1

	if actor != "" {
		baseQuery += fmt.Sprintf(" AND actor = $%d", paramIdx)
		params = append(params, actor)
		paramIdx++
	}
	if action != "" {
		baseQuery += fmt.Sprintf(" AND action = $%d", paramIdx)
		params = append(params, action)
		paramIdx++
	}
	if query != "" {
		baseQuery += fmt.Sprintf(" AND (target ILIKE $%d OR reason ILIKE $%d)", paramIdx, paramIdx)
		params = append(params, "%"+query+"%")
		paramIdx++
	}

	// Get total count
	countQuery := strings.Replace(baseQuery, "id, timestamp, actor, action, target, reason", "COUNT(*)", 1)
	err := p.readDb.Get(&total, countQuery, params...)
	if err != nil {
		return nil, 0, err
	}

	// Get records
	baseQuery += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", paramIdx, paramIdx+1)
	params = append(params, limit, offset)

	err = p.readDb.Select(&logs, baseQuery, params...)
	return logs, total, err
}

func (p *PostgresRepository) GetBlockTrend() ([]models.BlockTrend, error) {
	var trend []models.BlockTrend
	// Query for hourly counts in the last 24 hours
	query := `
		SELECT 
			to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD HH24:00') as hour,
			count(*) as count
		FROM audit_logs
		WHERE action IN ('BLOCK', 'BULK_BLOCK', 'BLOCK_PERSISTENT', 'BLOCK_EPHEMERAL') 
		  AND timestamp > NOW() - INTERVAL '24 hours'
		GROUP BY 1
		ORDER BY 1 ASC
	`
	err := p.readDb.Select(&trend, query)
	return trend, err
}

func (p *PostgresRepository) GetIPHistory(ip string) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := p.readDb.Select(&logs, "SELECT id, timestamp, actor, action, target, reason FROM audit_logs WHERE target = $1 ORDER BY timestamp DESC", ip)
	return logs, err
}
