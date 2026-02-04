package service

import (
	"context"
	"encoding/json"
	"strings"

	zlog "github.com/rs/zerolog/log"

	"blocklist/internal/config"
	"blocklist/internal/models"
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

func (s *WebhookService) Notify(ctx context.Context, event string, data interface{}) {
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
		if !matched {
			continue
		}

		// Geo Filter check
		if wh.GeoFilter != "" {
			if eventData, ok := data.(map[string]interface{}); ok {
				var entry *models.IPEntry
				switch e := eventData["data"].(type) {
				case models.IPEntry:
					entry = &e
				case *models.IPEntry:
					entry = e
				}

				if entry != nil && entry.Geolocation != nil {
					country := strings.ToUpper(entry.Geolocation.Country)
					filters := strings.Split(strings.ToUpper(wh.GeoFilter), ",")
					match := false
					for _, f := range filters {
						if strings.TrimSpace(f) == country {
							match = true
							break
						}
					}
					if !match {
						continue
					}
				}
			}
		}

		task, err := tasks.NewWebhookDeliveryTask(wh.ID, event, payload)
		if err != nil {
			zlog.Error().Err(err).Int("webhook_id", wh.ID).Str("event", event).Msg("Error creating webhook task")
			continue
		}

		task, err = tasks.NewWebhookDeliveryTask(wh.ID, event, payload)
		if err != nil {
			zlog.Error().Err(err).Int("webhook_id", wh.ID).Str("event", event).Msg("Error creating webhook task")
			continue
		}

		if _, err = s.asynqClient.Enqueue(task); err != nil {
			zlog.Error().Err(err).Int("webhook_id", wh.ID).Str("event", event).Msg("Error enqueuing webhook task")
		}
	}
}

func (s *WebhookService) Close() {
	if s.asynqClient != nil {
		s.asynqClient.Close()
	}
}
