package service

import (
	"context"
	"testing"

	"blocklist/internal/config"
	"github.com/hibiken/asynq"
)

func TestWebhookService_Notify_Disabled(t *testing.T) {
	cfg := &config.Config{EnableOutboundWebhooks: false}
	svc := NewWebhookService(nil, cfg, asynq.RedisClientOpt{})

	// This should return immediately
	svc.Notify(context.Background(), "block", map[string]string{"ip": "1.1.1.1"})
}
