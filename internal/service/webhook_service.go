package service

import (
	"context"
	"encoding/json"
	"log"
	"strings"

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
	if s.pgRepo == nil { return }

	webhooks, err := s.pgRepo.GetActiveWebhooks()
	if err != nil {
		log.Printf("Error fetching active webhooks: %v", err)
		return
	}

	payload, _ := json.Marshal(data)

	for _, wh := range webhooks {
		if strings.Contains(wh.Events, event) {
			// Geo Filter check
			if wh.GeoFilter != "" {
				if eventData, ok := data.(map[string]interface{}); ok {
					if entry, ok := eventData["data"].(*models.IPEntry); ok && entry.Geolocation != nil {
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
				log.Printf("Error creating task: %v", err)
				continue
			}
			
			if _, err := s.asynqClient.Enqueue(task); err != nil {
				log.Printf("Error enqueuing task: %v", err)
			}
		}
	}
}

func (s *WebhookService) Close() {
	if s.asynqClient != nil {
		s.asynqClient.Close()
	}
}
