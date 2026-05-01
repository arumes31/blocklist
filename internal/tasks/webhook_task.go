package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/security"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"

	"github.com/hibiken/asynq"
)

const (
	TypeWebhookDelivery = "webhook:deliver"
)

// WebhookRepository defines the database operations needed for webhook tasks.
type WebhookRepository interface {
	GetActiveWebhooks() ([]models.OutboundWebhook, error)
	LogWebhookDelivery(logEntry models.WebhookLog) error
}

type WebhookPayload struct {
	WebhookID int    `json:"webhook_id"`
	Event     string `json:"event"`
	Data      []byte `json:"data"`
}

// NewWebhookDeliveryTask creates a task for webhook delivery.
func NewWebhookDeliveryTask(webhookID int, event string, data []byte) (*asynq.Task, error) {
	payload, err := json.Marshal(WebhookPayload{
		WebhookID: webhookID,
		Event:     event,
		Data:      data,
	})
	if err != nil {
		return nil, err
	}
	// Max retry is default (25), we can tune this
	return asynq.NewTask(TypeWebhookDelivery, payload, asynq.MaxRetry(5), asynq.Timeout(20*time.Second)), nil
}

// WebhookTaskHandler handles webhook delivery tasks.
type WebhookTaskHandler struct {
	repo   WebhookRepository
	client *http.Client
}

func NewWebhookTaskHandler(repo WebhookRepository) *WebhookTaskHandler {
	return NewWebhookTaskHandlerWithClient(repo, nil)
}

func NewWebhookTaskHandlerWithClient(repo WebhookRepository, client *http.Client) *WebhookTaskHandler {
	if client == nil {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
			Control:   security.SafeSocketControl,
		}
		transport := &http.Transport{
			DialContext: dialer.DialContext,
		}
		client = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	}
	return &WebhookTaskHandler{
		repo:   repo,
		client: client,
	}
}

func (h *WebhookTaskHandler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var p WebhookPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}

	// Fetch webhook details fresh to ensure it's still active/valid
	// (Note: In a high-throughput system, you might pass the URL/Secret in payload to avoid DB hit,
	// but passing ID ensures we respect updates/deletions that happened while in queue)
	// For now, we'll assume we need to re-fetch the webhook details from DB or cache.
	// Since GetActiveWebhooks returns a list, let's implement a GetWebhookByID in repository or find it.
	// For simplicity, we might iterate or add a helper.
	// Optimization: If the payload contained URL/Secret, we wouldn't need a DB lookup,
	// but we risk sending to a deleted webhook. Let's look it up.

	// Since we don't have GetWebhookByID yet, we can add it or scan.
	// Let's rely on the payload having enough info if we trust the enqueuer, OR add the method.
	// Let's add GetWebhookByID to PostgresRepository.

	// Temporarily: we will fetch all active and find ours.
	webhooks, err := h.repo.GetActiveWebhooks()
	if err != nil {
		return fmt.Errorf("failed to fetch webhooks: %v", err)
	}

	var webhook *models.OutboundWebhook
	for _, wh := range webhooks {
		if wh.ID == p.WebhookID {
			webhook = &wh
			break
		}
	}

	if webhook == nil {
		// Webhook no longer active or deleted
		return nil // Do not retry
	}

	req, err := http.NewRequest("POST", webhook.URL, bytes.NewBuffer(p.Data))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Blocklist-Event", p.Event)

	// Attempt tracking is handled by Asynq automatically via Retried field if we wanted to access it,
	// but for our custom headers:
	retryCount, _ := asynq.GetRetryCount(ctx)
	req.Header.Set("X-Blocklist-Attempt", fmt.Sprintf("%d", retryCount+1))

	if webhook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(webhook.Secret))
		mac.Write(p.Data)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Blocklist-Signature", signature)
	}

	resp, err := h.client.Do(req)

	logEntry := models.WebhookLog{
		WebhookID: webhook.ID,
		Event:     p.Event,
		Payload:   string(p.Data),
		Attempt:   retryCount + 1,
	}

	if err != nil {
		logEntry.Error = err.Error()
		_ = h.repo.LogWebhookDelivery(logEntry)
		return fmt.Errorf("request failed: %v", err)
	}

	logEntry.StatusCode = resp.StatusCode
	// Limit to 1MB to prevent unconstrained resource consumption (CWE-400)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	logEntry.ResponseBody = string(body)
	_ = resp.Body.Close()

	_ = h.repo.LogWebhookDelivery(logEntry)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
