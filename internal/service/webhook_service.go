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

type WebhookService struct {
	pgRepo *repository.PostgresRepository
	cfg    *config.Config
	client *http.Client
}

func NewWebhookService(pg *repository.PostgresRepository, cfg *config.Config) *WebhookService {
	return &WebhookService{
		pgRepo: pg,
		cfg:    cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
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
			go s.sendWithRetry(wh, event, payload, 1)
		}
	}
}

func (s *WebhookService) sendWithRetry(wh models.OutboundWebhook, event string, payload []byte, attempt int) {
	req, err := http.NewRequest("POST", wh.URL, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Error creating webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Blocklist-Event", event)
	req.Header.Set("X-Blocklist-Attempt", fmt.Sprintf("%d", attempt))

	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write(payload)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Blocklist-Signature", signature)
	}

	resp, err := s.client.Do(req)
	
	logEntry := models.WebhookLog{
		WebhookID: wh.ID,
		Event:     event,
		Payload:   string(payload),
		Attempt:   attempt,
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

	if (err != nil || logEntry.StatusCode >= 400) && attempt < 3 {
		time.Sleep(time.Duration(attempt*attempt) * time.Minute) // Exponential backoff
		s.sendWithRetry(wh, event, payload, attempt+1)
	}
}
