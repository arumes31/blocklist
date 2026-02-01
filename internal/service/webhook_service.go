package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"
)

type WebhookTask struct {
	Webhook models.OutboundWebhook `json:"webhook"`
	Event   string                 `json:"event"`
	Payload []byte                 `json:"payload"`
	Attempt int                    `json:"attempt"`
}

type WebhookService struct {
	pgRepo    *repository.PostgresRepository
	redisRepo *repository.RedisRepository
	cfg       *config.Config
	client    *http.Client
	queueKey  string
}

func NewWebhookService(pg *repository.PostgresRepository, redis *repository.RedisRepository, cfg *config.Config) *WebhookService {
	return &WebhookService{
		pgRepo:    pg,
		redisRepo: redis,
		cfg:       cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		queueKey: "webhook_tasks",
	}
}

func (s *WebhookService) Start(ctx context.Context) {
	for i := 0; i < 5; i++ { // 5 workers
		go s.worker(ctx)
	}
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
			
			task := WebhookTask{
				Webhook: wh,
				Event:   event,
				Payload: payload,
				Attempt: 1,
			}
			s.enqueue(task)
		}
	}
}

func (s *WebhookService) enqueue(task WebhookTask) {
	data, _ := json.Marshal(task)
	_ = s.redisRepo.GetClient().LPush(context.Background(), s.queueKey, data).Err()
}

func (s *WebhookService) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			res, err := s.redisRepo.GetClient().BRPop(ctx, 0, s.queueKey).Result()
			if err != nil {
				continue
			}

			var task WebhookTask
			if err := json.Unmarshal([]byte(res[1]), &task); err != nil {
				continue
			}

			s.processTask(task)
		}
	}
}

func (s *WebhookService) processTask(task WebhookTask) {
	req, err := http.NewRequest("POST", task.Webhook.URL, bytes.NewBuffer(task.Payload))
	if err != nil {
		log.Printf("Error creating webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Blocklist-Event", task.Event)
	req.Header.Set("X-Blocklist-Attempt", fmt.Sprintf("%d", task.Attempt))

	if task.Webhook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(task.Webhook.Secret))
		mac.Write(task.Payload)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Blocklist-Signature", signature)
	}

	resp, err := s.client.Do(req)
	
	logEntry := models.WebhookLog{
		WebhookID: task.Webhook.ID,
		Event:     task.Event,
		Payload:   string(task.Payload),
		Attempt:   task.Attempt,
	}

	if err != nil {
		logEntry.Error = err.Error()
	} else {
		logEntry.StatusCode = resp.StatusCode
		body, _ := io.ReadAll(resp.Body)
		logEntry.ResponseBody = string(body)
		resp.Body.Close()
	}

	if s.pgRepo != nil {
		_ = s.pgRepo.LogWebhookDelivery(logEntry)
	}

	if (err != nil || logEntry.StatusCode >= 400) && task.Attempt < 3 {
		// Re-enqueue with delay
		time.AfterFunc(time.Duration(task.Attempt*task.Attempt)*time.Minute, func() {
			task.Attempt++
			s.enqueue(task)
		})
	}
}
