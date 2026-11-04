package service

import (
	"context"
	"encoding/json"
	"strings"

	zlog "github.com/rs/zerolog/log"

	"blocklist/internal/config"
	"blocklist/internal/repository"
	"blocklist/internal/tasks"

	"github.com/hibiken/asynq"
)

type WebhookService struct {
	pgRepo      *repository.PostgresRepository
	cfg         *config.Config
	asynqClient *asynq.Client
}

func NewWebhookService(pg *repository.PostgresRepository, cfg *config.Config, redisOpts asynq.RedisClientOpt) *WebhookService {
	return &WebhookService{
		pgRepo:      pg,
		cfg:         cfg,
		asynqClient: asynq.NewClient(redisOpts),
	}
}

// Start is deprecated/no-op as workers are now handled by asynq.Server in main
func (s *WebhookService) Start(ctx context.Context) {
	// No-op
}

// Notify enqueues event for every active receiver subscribed to it.
// targetCountry is the ISO country code of the event's target address, or ""
// when it is unknown. A receiver with a country filter only receives events
// whose target country is known and listed; the decision never depends on the
// shape of data.
func (s *WebhookService) Notify(ctx context.Context, event string, targetCountry string, data interface{}) {
	if s.cfg != nil && !s.cfg.EnableOutboundWebhooks {
		return
	}
	if s.pgRepo == nil {
		return
	}

	webhooks, err := s.pgRepo.GetActiveWebhooks()
	if err != nil {
		zlog.Error().Err(err).Msg("Error fetching active webhooks")
		return
	}

	payload, err := json.Marshal(data)
	if err != nil {
		zlog.Error().Err(err).Str("event", event).Msg("Error marshaling webhook payload")
		return
	}

	for _, wh := range webhooks {
		// Exact event match check (comma-separated list)
		matched := false
		for _, e := range strings.Split(wh.Events, ",") {
			if strings.TrimSpace(e) == event {
				matched = true
				break
			}
		}
		if !matched || !geoFilterAllows(wh.GeoFilter, targetCountry) {
			continue
		}

		task, err := tasks.NewWebhookDeliveryTask(wh.ID, event, payload)
		if err != nil {
			zlog.Error().Err(err).Int("webhook_id", wh.ID).Str("event", event).Msg("Error creating webhook task")
			continue
		}

		if _, err = s.asynqClient.Enqueue(task); err != nil {
			zlog.Error().Err(err).Int("webhook_id", wh.ID).Str("event", event).Msg("Error enqueuing webhook task")
		}
	}
}

// geoFilterAllows reports whether a receiver's comma-separated country filter
// admits an event targeting country. An empty filter admits everything; a
// configured filter withholds events whose country is unknown.
func geoFilterAllows(filter, country string) bool {
	if strings.TrimSpace(filter) == "" {
		return true
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	if country == "" {
		return false
	}
	for _, f := range strings.Split(strings.ToUpper(filter), ",") {
		if strings.TrimSpace(f) == country {
			return true
		}
	}
	return false
}

func (s *WebhookService) Close() {
	if s.asynqClient != nil {
		_ = s.asynqClient.Close()
	}
}
