package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	SecretKey              string
	RedisHost              string
	RedisPort              int
	RedisPassword          string
	RedisDB                int
	RedisLimDB             int
	PostgresURL            string
	PostgresReadURL        string
	GUIAdmin               string
	GUIPassword            string
	GUIToken               string
	LogWeb                 bool
	BlockedRanges          string
	GeoIPAccountID         string
	GeoIPLicenseKey        string
	TrustedProxies         string
	UseCloudflare          bool
	Port                   string
	MetricsAllowedIPs      string
	EnableOutboundWebhooks bool
	DisableGUIAdminLogin   bool
	RateLimit              int
	RatePeriod             int
	RateLimitLogin         int
	RateLimitWebhook       int
	LogRetentionMonths     int
	CookieSecure           bool
	SameSiteStrict         bool
	ForceHTTPS             bool
	RunWorkerInProcess     bool
	AuditLogLimitPerIP     int
}

func Load() *Config {
	return &Config{
		SecretKey:              getEnv("SECRET_KEY", "change-me"),
		RedisHost:              getEnv("REDIS_HOST", "localhost"),
		RedisPort:              getEnvInt("REDIS_PORT", 6379),
		RedisPassword:          getEnv("REDIS_PASSWORD", ""),
		RedisDB:                getEnvInt("REDIS_DB", 0),
		RedisLimDB:             getEnvInt("REDIS_LIM_DB", 1),
		PostgresURL:            getEnv("POSTGRES_URL", "postgres://postgres:password@localhost:5432/blocklist?sslmode=disable"),
		PostgresReadURL:        getEnv("POSTGRES_READ_URL", getEnv("POSTGRES_URL", "postgres://postgres:password@localhost:5432/blocklist?sslmode=disable")),
		GUIAdmin:               getEnv("GUIAdmin", "admin"),
		GUIPassword:            getEnv("GUIPassword", "password"),
		GUIToken:               getEnv("GUIToken", ""),
		LogWeb:                 getEnvBool("LOGWEB", false),
		BlockedRanges:          getEnv("BLOCKED_RANGES", ""),
		GeoIPAccountID:         getEnv("GEOIPUPDATE_ACCOUNT_ID", ""),
		GeoIPLicenseKey:        getEnv("GEOIPUPDATE_LICENSE_KEY", ""),
		TrustedProxies:         getEnv("TRUSTED_PROXIES", "127.0.0.1"),
		UseCloudflare:          getEnvBool("USE_CLOUDFLARE", false),
		Port:                   getEnv("PORT", "5000"),
		MetricsAllowedIPs:      getEnv("METRICS_ALLOWED_IPS", "127.0.0.1"),
		EnableOutboundWebhooks: getEnvBool("ENABLE_OUTBOUND_WEBHOOKS", false),
		DisableGUIAdminLogin:   getEnvBool("DISABLE_GUIADMIN_LOGIN", false),
		RateLimit:              getEnvInt("RATE_LIMIT", 500),
		RatePeriod:             getEnvInt("RATE_PERIOD", 30),
		RateLimitLogin:         getEnvInt("RATE_LIMIT_LOGIN", 10),
		RateLimitWebhook:       getEnvInt("RATE_LIMIT_WEBHOOK", 100),
		LogRetentionMonths:     getEnvInt("LOG_RETENTION_MONTHS", 6),
		CookieSecure:           getEnvBool("COOKIE_SECURE", false),
		SameSiteStrict:         getEnvBool("COOKIE_SAMESITE_STRICT", false),
		ForceHTTPS:             getEnvBool("FORCE_HTTPS", false),
		RunWorkerInProcess:     getEnvBool("RUN_WORKER_IN_PROCESS", true),
		AuditLogLimitPerIP:     getEnvInt("AUDIT_LOG_LIMIT_PER_IP", 100),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return value == "true" || value == "1"
	}
	return fallback
}
