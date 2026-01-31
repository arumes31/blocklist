package config

import (
	"os"
	"strconv"
)

type Config struct {
	SecretKey            string
	RedisHost            string
	RedisPort            int
	RedisDB              int
	RedisLimDB           int
	PostgresURL          string
	GUIAdmin             string
	GUIPassword          string
	GUIToken             string
	LogWeb               bool
	BlockedRanges        string
	Webhook2AllowedIPs   string
	GeoIPAccountID       string
	GeoIPLicenseKey      string
	TrustedProxies       string
		UseCloudflare        bool
			Port                 string
			WebhookSecret        string
			MetricsAllowedIPs    string
		}
			func Load() *Config {
		return &Config{
			SecretKey:          getEnv("SECRET_KEY", "change-me"),
			RedisHost:          getEnv("REDIS_HOST", "localhost"),
			RedisPort:          getEnvInt("REDIS_PORT", 6379),
			RedisDB:            getEnvInt("REDIS_DB", 0),
			RedisLimDB:         getEnvInt("REDIS_LIM_DB", 1),
			PostgresURL:        getEnv("POSTGRES_URL", "postgres://postgres:password@localhost:5432/blocklist?sslmode=disable"),
			GUIAdmin:           getEnv("GUIAdmin", "admin"),
			GUIPassword:        getEnv("GUIPassword", "password"),
			GUIToken:           getEnv("GUIToken", ""),
			LogWeb:             getEnvBool("LOGWEB", false),
			BlockedRanges:      getEnv("BLOCKED_RANGES", ""),
			Webhook2AllowedIPs: getEnv("WEBHOOK2_ALLOWED_IPS", "127.0.0.1"),
			GeoIPAccountID:     getEnv("GEOIPUPDATE_ACCOUNT_ID", ""),	
			GeoIPLicenseKey:    getEnv("GEOIPUPDATE_LICENSE_KEY", ""),
			TrustedProxies:     getEnv("TRUSTED_PROXIES", "127.0.0.1"),
			UseCloudflare:      getEnvBool("USE_CLOUDFLARE", false),
					Port:               getEnv("PORT", "5000"),
					WebhookSecret:      getEnv("WEBHOOK_SECRET", ""),
					MetricsAllowedIPs:  getEnv("METRICS_ALLOWED_IPS", "127.0.0.1"),
				}
			}
			
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
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
