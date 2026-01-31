package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/models"
)

func TestWebhookService_Notify_Disabled(t *testing.T) {
	cfg := &config.Config{EnableOutboundWebhooks: false}
	svc := NewWebhookService(nil, cfg)

	// This should return immediately
	svc.Notify(context.Background(), "block", map[string]string{"ip": "1.1.1.1"})
}

func TestWebhookService_SendWithRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewWebhookService(nil, &config.Config{EnableOutboundWebhooks: true})
	wh := models.OutboundWebhook{
		URL:    server.URL,
		Events: "block",
		Secret: "secret",
	}

	// Test direct send
	svc.sendWithRetry(wh, "block", []byte(`{"ip":"1.1.1.1"}`), 1)
}
