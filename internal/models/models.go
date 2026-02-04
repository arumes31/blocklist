package models

type GeoData struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ASN       uint    `json:"asn,omitempty"`
	ASNOrg    string  `json:"asn_org,omitempty"`
}

type IPEntry struct {
	Timestamp   string   `json:"timestamp"`
	Geolocation *GeoData `json:"geolocation"`
	Reason      string   `json:"reason"`
	AddedBy     string   `json:"added_by"`
	TTL         int      `json:"ttl,omitempty"`        // TTL in seconds
	ExpiresAt   string   `json:"expires_at,omitempty"` // Absolute expiration time
	ThreatScore int      `json:"threat_score,omitempty"`
}

type WhitelistEntry struct {
	Timestamp   string   `json:"timestamp"`
	Geolocation *GeoData `json:"geolocation"`
	AddedBy     string   `json:"added_by"`
	Reason      string   `json:"reason"`
	ExpiresIn   string   `json:"expires_in,omitempty"`
}

type AuditLog struct {
	ID        int    `json:"id" db:"id"`
	Timestamp string `json:"timestamp" db:"timestamp"`
	Actor     string `json:"actor" db:"actor"`
	Action    string `json:"action" db:"action"`
	Target    string `json:"target" db:"target"`
	Reason    string `json:"reason" db:"reason"`
}

type AdminAccount struct {
	Username       string `json:"username" db:"username"`
	PasswordHash   string `json:"password_hash" db:"password_hash"`
	Token          string `json:"token" db:"token"`
	Role           string `json:"role" db:"role"`
	Permissions    string `json:"permissions" db:"permissions"`
	SessionVersion int    `json:"session_version" db:"session_version"`
}

type APIToken struct {
	ID          int     `json:"id" db:"id"`
	TokenHash   string  `json:"-" db:"token_hash"` // SHA256 sum of the raw token
	Name        string  `json:"name" db:"name"`
	Username    string  `json:"username" db:"username"`
	Role        string  `json:"role" db:"role"`
	Permissions string  `json:"permissions" db:"permissions"`
	AllowedIPs  string  `json:"allowed_ips" db:"allowed_ips"` // Comma-separated CIDRs
	CreatedAt   string  `json:"created_at" db:"created_at"`
	ExpiresAt   *string `json:"expires_at" db:"expires_at"`
	LastUsed    *string `json:"last_used" db:"last_used"`
	LastUsedIP  string  `json:"last_used_ip" db:"last_used_ip"`
}

type SavedView struct {
	ID        int    `json:"id" db:"id"`
	Username  string `json:"username" db:"username"`
	Name      string `json:"name" db:"name"`
	Filters   string `json:"filters" db:"filters"` // JSON string of filters
	CreatedAt string `json:"created_at" db:"created_at"`
}

type OutboundWebhook struct {
	ID        int    `json:"id" db:"id"`
	URL       string `json:"url" db:"url"`
	Events    string `json:"events" db:"events"`
	Secret    string `json:"secret" db:"secret"`
	GeoFilter string `json:"geo_filter" db:"geo_filter"`
	Active    bool   `json:"active" db:"active"`
	CreatedAt string `json:"created_at" db:"created_at"`
}

type WebhookLog struct {
	ID           int    `json:"id" db:"id"`
	WebhookID    int    `json:"webhook_id" db:"webhook_id"`
	Event        string `json:"event" db:"event"`
	Payload      string `json:"payload" db:"payload"`
	StatusCode   int    `json:"status_code" db:"status_code"`
	ResponseBody string `json:"response_body" db:"response_body"`
	Error        string `json:"error" db:"error"`
	Attempt      int    `json:"attempt" db:"attempt"`
	Timestamp    string `json:"timestamp" db:"timestamp"`
}
