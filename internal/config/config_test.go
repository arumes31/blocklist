package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	// Save original env
	origSecret := os.Getenv("SECRET_KEY")
	origPort := os.Getenv("PORT")
	defer func() {
		_ = os.Setenv("SECRET_KEY", origSecret)
		_ = os.Setenv("PORT", origPort)
	}()

	_ = os.Setenv("SECRET_KEY", "test-secret")
	_ = os.Setenv("PORT", "9999")
	_ = os.Setenv("ENABLE_OUTBOUND_WEBHOOKS", "true")

	cfg := Load()

	if cfg.SecretKey != "test-secret" {
		t.Errorf("expected test-secret, got %s", cfg.SecretKey)
	}
	if cfg.Port != "9999" {
		t.Errorf("expected 9999, got %s", cfg.Port)
	}
	if cfg.GUIPassword != "" {
		t.Errorf("expected empty GUIPassword default, got %s", cfg.GUIPassword)
	}
	if !cfg.EnableOutboundWebhooks {
		t.Error("expected EnableOutboundWebhooks to be true")
	}
}

func TestGetEnv(t *testing.T) {
	val := getEnv("NON_EXISTENT_VAR", "fallback")
	if val != "fallback" {
		t.Errorf("expected fallback, got %s", val)
	}
}

func TestGetEnvInt(t *testing.T) {
	_ = os.Setenv("TEST_INT", "123")
	val := getEnvInt("TEST_INT", 0)
	if val != 123 {
		t.Errorf("expected 123, got %d", val)
	}

	val2 := getEnvInt("NON_EXISTENT_INT", 456)
	if val2 != 456 {
		t.Errorf("expected 456, got %d", val2)
	}
}

func TestGetEnvBool(t *testing.T) {
	_ = os.Setenv("TEST_BOOL_TRUE", "true")
	if !getEnvBool("TEST_BOOL_TRUE", false) {
		t.Error("expected true for 'true'")
	}

	_ = os.Setenv("TEST_BOOL_1", "1")
	if !getEnvBool("TEST_BOOL_1", false) {
		t.Error("expected true for '1'")
	}

	_ = os.Setenv("TEST_BOOL_FALSE", "false")
	if getEnvBool("TEST_BOOL_FALSE", true) {
		t.Error("expected false for 'false'")
	}
}

func TestTrustedProxyListReplacesPrivateRanges(t *testing.T) {
	if got := (&Config{TrustedProxies: "127.0.0.1"}).TrustedProxyList(); len(got) != 3 || got[2] != "127.0.0.1/32" {
		t.Errorf("unexpected default list %v", got)
	}
	got := (&Config{TrustedProxies: "10.1.2.3, 2001:db8::1, 192.0.2.0/24"}).TrustedProxyList()
	want := []string{"127.0.0.1/32", "::1/128", "10.1.2.3/32", "2001:db8::1/128", "192.0.2.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
	for _, prefix := range (&Config{TrustedProxies: "none"}).TrustedProxyList() {
		if prefix == "10.0.0.0/8" || prefix == "192.168.0.0/16" || prefix == "172.16.0.0/12" {
			t.Errorf("private range %s must not be trusted implicitly", prefix)
		}
	}
}

func TestSecureDefaults(t *testing.T) {
	for _, key := range []string{"COOKIE_SECURE", "ALLOW_BASIC_AUTH", "POSTGRES_URL", "POSTGRES_READ_URL"} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	cfg := Load()
	if !cfg.CookieSecure {
		t.Error("expected Secure cookies by default")
	}
	if cfg.AllowBasicAuth {
		t.Error("expected Basic auth to be disabled by default")
	}
	if cfg.PostgresURL != "" || cfg.PostgresReadURL != "" {
		t.Error("expected no credentialed default database URL")
	}
}
