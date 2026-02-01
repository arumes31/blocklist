package repository

import (
	"blocklist/internal/models"
	"encoding/json"
	"time"
	"github.com/jmoiron/sqlx"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresRepository struct {
	db *sqlx.DB
}

func NewPostgresRepository(url string) (*PostgresRepository, error) {
	db, err := sqlx.Connect("pgx", url)
	if err != nil {
		return nil, err
	}

	// Improvement 2: Connection Pooling
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &PostgresRepository{db: db}, nil
}

func (p *PostgresRepository) GetAdmin(username string) (*models.AdminAccount, error) {
	var admin models.AdminAccount
	err := p.db.Get(&admin, "SELECT username, password_hash, token, role, permissions FROM admins WHERE username = $1", username)
	if err != nil {
		return nil, err
	}
	return &admin, nil
}

func (p *PostgresRepository) CreateAdmin(admin models.AdminAccount) error {
	if admin.Role == "" { admin.Role = "operator" }
	if admin.Permissions == "" { admin.Permissions = "gui_read" }
	_, err := p.db.NamedExec("INSERT INTO admins (username, password_hash, token, role, permissions) VALUES (:username, :password_hash, :token, :role, :permissions)", admin)
	return err
}

func (p *PostgresRepository) UpdateAdminPassword(username, hash string) error {
	_, err := p.db.Exec("UPDATE admins SET password_hash = $1 WHERE username = $2", hash, username)
	return err
}

func (p *PostgresRepository) UpdateAdminToken(username, token string) error {
	_, err := p.db.Exec("UPDATE admins SET token = $1 WHERE username = $2", token, username)
	return err
}

func (p *PostgresRepository) UpdateAdminPermissions(username, permissions string) error {
	_, err := p.db.Exec("UPDATE admins SET permissions = $1 WHERE username = $2", permissions, username)
	return err
}

func (p *PostgresRepository) DeleteAdmin(username string) error {
	_, err := p.db.Exec("DELETE FROM admins WHERE username = $1", username)
	return err
}

func (p *PostgresRepository) GetAllAdmins() ([]models.AdminAccount, error) {
	var admins []models.AdminAccount
	err := p.db.Select(&admins, "SELECT username, password_hash, token, role, permissions FROM admins")
	return admins, err
}

func (p *PostgresRepository) CreateAPIToken(token models.APIToken) error {
	_, err := p.db.NamedExec("INSERT INTO api_tokens (token_hash, name, username, role, expires_at) VALUES (:token_hash, :name, :username, :role, :expires_at)", token)
	return err
}

func (p *PostgresRepository) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	var token models.APIToken
	err := p.db.Get(&token, "SELECT id, token_hash, name, username, role, created_at, expires_at, last_used FROM api_tokens WHERE token_hash = $1", hash)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (p *PostgresRepository) GetAPITokens(username string) ([]models.APIToken, error) {
	var tokens []models.APIToken
	err := p.db.Select(&tokens, "SELECT id, name, username, role, created_at, expires_at, last_used FROM api_tokens WHERE username = $1 ORDER BY created_at DESC", username)
	return tokens, err
}

func (p *PostgresRepository) DeleteAPIToken(id int, username string) error {
	_, err := p.db.Exec("DELETE FROM api_tokens WHERE id = $1 AND username = $2", id, username)
	return err
}

func (p *PostgresRepository) UpdateTokenLastUsed(id int) error {
	_, err := p.db.Exec("UPDATE api_tokens SET last_used = NOW() WHERE id = $1", id)
	return err
}

func (p *PostgresRepository) CreateSavedView(view models.SavedView) error {
	_, err := p.db.NamedExec("INSERT INTO saved_views (username, name, filters) VALUES (:username, :name, :filters)", view)
	return err
}

func (p *PostgresRepository) GetSavedViews(username string) ([]models.SavedView, error) {
	var views []models.SavedView
	err := p.db.Select(&views, "SELECT id, username, name, filters, created_at FROM saved_views WHERE username = $1 ORDER BY created_at DESC", username)
	return views, err
}

func (p *PostgresRepository) DeleteSavedView(id int, username string) error {
	_, err := p.db.Exec("DELETE FROM saved_views WHERE id = $1 AND username = $2", id, username)
	return err
}

func (p *PostgresRepository) GetActiveWebhooks() ([]models.OutboundWebhook, error) {
	var webhooks []models.OutboundWebhook
	err := p.db.Select(&webhooks, "SELECT id, url, events, secret, active, created_at FROM outbound_webhooks WHERE active = TRUE")
	return webhooks, err
}

func (p *PostgresRepository) LogWebhookDelivery(logEntry models.WebhookLog) error {
	_, err := p.db.NamedExec("INSERT INTO webhook_logs (webhook_id, event, payload, status_code, response_body, error, attempt) VALUES (:webhook_id, :event, :payload, :status_code, :response_body, :error, :attempt)", logEntry)
	return err
}

func (p *PostgresRepository) CreateOutboundWebhook(wh models.OutboundWebhook) error {
	_, err := p.db.NamedExec("INSERT INTO outbound_webhooks (url, events, secret, active) VALUES (:url, :events, :secret, :active)", wh)
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
	err := p.db.Select(&results, "SELECT ip, timestamp, reason, added_by, geo_json FROM persistent_blocks")
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

func (p *PostgresRepository) GetPersistentCount() (int, error) {
	var count int
	err := p.db.Get(&count, "SELECT COUNT(*) FROM persistent_blocks")
	return count, err
}

func (p *PostgresRepository) LogAction(actor, action, target, reason string) error {
	_, err := p.db.Exec("INSERT INTO audit_logs (actor, action, target, reason) VALUES ($1, $2, $3, $4)", actor, action, target, reason)
	return err
}

func (p *PostgresRepository) GetAuditLogs(limit int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := p.db.Select(&logs, "SELECT id, timestamp, actor, action, target, reason FROM audit_logs ORDER BY timestamp DESC LIMIT $1", limit)
	return logs, err
}
