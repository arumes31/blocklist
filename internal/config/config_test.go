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
		os.Setenv("SECRET_KEY", origSecret)
		os.Setenv("PORT", origPort)
	}()

	os.Setenv("SECRET_KEY", "test-secret")
	os.Setenv("PORT", "9999")
	os.Setenv("ENABLE_OUTBOUND_WEBHOOKS", "true")

	cfg := Load()

	if cfg.SecretKey != "test-secret" {
		t.Errorf("expected test-secret, got %s", cfg.SecretKey)
	}
	if cfg.Port != "9999" {
		t.Errorf("expected 9999, got %s", cfg.Port)
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
	os.Setenv("TEST_INT", "123")
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
	os.Setenv("TEST_BOOL_TRUE", "true")
	if !getEnvBool("TEST_BOOL_TRUE", false) {
		t.Error("expected true for 'true'")
	}

	os.Setenv("TEST_BOOL_1", "1")
	if !getEnvBool("TEST_BOOL_1", false) {
		t.Error("expected true for '1'")
	}

	os.Setenv("TEST_BOOL_FALSE", "false")
	if getEnvBool("TEST_BOOL_FALSE", true) {
		t.Error("expected false for 'false'")
	}
}
