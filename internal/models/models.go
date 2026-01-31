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
}

type WhitelistEntry struct {
	Timestamp   string   `json:"timestamp"`
	Geolocation *GeoData `json:"geolocation"`
	AddedBy     string   `json:"added_by"`
	Reason      string   `json:"reason"`
	ExpiresIn   string   `json:"expires_in,omitempty"`
}

type AdminAccount struct {
	Username     string `json:"username" db:"username"`
	PasswordHash string `json:"password_hash" db:"password_hash"`
	Token        string `json:"token" db:"token"`
	Role         string `json:"role" db:"role"`
}

type APIToken struct {
	ID        int      `json:"id" db:"id"`
	TokenHash string   `json:"-" db:"token_hash"`
	Name      string   `json:"name" db:"name"`
	Username  string   `json:"username" db:"username"`
	Role      string   `json:"role" db:"role"`
	CreatedAt string   `json:"created_at" db:"created_at"`
	ExpiresAt *string  `json:"expires_at" db:"expires_at"`
	LastUsed  *string  `json:"last_used" db:"last_used"`
}
