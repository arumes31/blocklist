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
	svc.Notify(context.Background(), "block", "", map[string]string{"ip": "1.1.1.1"})
}

func TestGeoFilterAllows(t *testing.T) {
	for _, tc := range []struct {
		filter, country string
		want            bool
	}{
		{"", "", true},
		{"", "AT", true},
		{"AT,DE", "at", true},
		{"AT, DE", "DE", true},
		{"AT,DE", "US", false},
		{"AT", "", false}, // unknown country never bypasses a configured filter
	} {
		if got := geoFilterAllows(tc.filter, tc.country); got != tc.want {
			t.Errorf("geoFilterAllows(%q, %q) = %v, want %v", tc.filter, tc.country, got, tc.want)
		}
	}
}
