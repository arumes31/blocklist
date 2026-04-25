package tasks

import (
	"blocklist/internal/models"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockWebhookRepository struct {
	mock.Mock
}

func (m *mockWebhookRepository) GetActiveWebhooks() ([]models.OutboundWebhook, error) {
	args := m.Called()
	return args.Get(0).([]models.OutboundWebhook), args.Error(1)
}

func (m *mockWebhookRepository) LogWebhookDelivery(logEntry models.WebhookLog) error {
	args := m.Called(logEntry)
	return args.Error(0)
}

func TestNewWebhookDeliveryTask(t *testing.T) {
	data := []byte(`{"ip":"1.2.3.4","action":"block"}`)
	task, err := NewWebhookDeliveryTask(123, "ip.blocked", data)

	require.NoError(t, err)
	require.NotNil(t, task)

	assert.Equal(t, TypeWebhookDelivery, task.Type())

	// Verify payload
	var payload WebhookPayload
	err = json.Unmarshal(task.Payload(), &payload)
	require.NoError(t, err)

	assert.Equal(t, 123, payload.WebhookID)
	assert.Equal(t, "ip.blocked", payload.Event)
	assert.Equal(t, data, payload.Data)
}

func TestWebhookTaskHandler_ProcessTask_InvalidPayload(t *testing.T) {
	repo := new(mockWebhookRepository)
	handler := NewWebhookTaskHandlerWithClient(repo, &http.Client{})

	task := asynq.NewTask(TypeWebhookDelivery, []byte("invalid json"))
	err := handler.ProcessTask(context.Background(), task)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "json.Unmarshal failed")
}

func TestWebhookTaskHandler_ProcessTask_Success(t *testing.T) {
	repo := new(mockWebhookRepository)
	handler := NewWebhookTaskHandlerWithClient(repo, &http.Client{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "ip.blocked", r.Header.Get("X-Blocklist-Event"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	webhooks := []models.OutboundWebhook{
		{
			ID:     123,
			URL:    server.URL,
			Active: true,
		},
	}

	repo.On("GetActiveWebhooks").Return(webhooks, nil)
	repo.On("LogWebhookDelivery", mock.Anything).Return(nil)

	data := []byte(`{"ip":"1.2.3.4"}`)
	task, err := NewWebhookDeliveryTask(123, "ip.blocked", data)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.NoError(t, err)

	repo.AssertExpectations(t)
}

func TestWebhookTaskHandler_ProcessTask_DeletedWebhook(t *testing.T) {
	repo := new(mockWebhookRepository)
	handler := NewWebhookTaskHandlerWithClient(repo, &http.Client{})

	repo.On("GetActiveWebhooks").Return([]models.OutboundWebhook{}, nil)

	data := []byte(`{"ip":"1.2.3.4"}`)
	task, err := NewWebhookDeliveryTask(123, "ip.blocked", data)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.NoError(t, err) // Should return nil when webhook not found

	repo.AssertExpectations(t)
}

func TestWebhookTaskHandler_ProcessTask_HTTPError(t *testing.T) {
	repo := new(mockWebhookRepository)
	handler := NewWebhookTaskHandlerWithClient(repo, &http.Client{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	webhooks := []models.OutboundWebhook{
		{
			ID:     123,
			URL:    server.URL,
			Active: true,
		},
	}

	repo.On("GetActiveWebhooks").Return(webhooks, nil)
	repo.On("LogWebhookDelivery", mock.Anything).Return(nil)

	data := []byte(`{"ip":"1.2.3.4"}`)
	task, err := NewWebhookDeliveryTask(123, "ip.blocked", data)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook returned status 500")

	repo.AssertExpectations(t)
}

func TestWebhookTaskHandler_ProcessTask_WithSecret(t *testing.T) {
	repo := new(mockWebhookRepository)
	handler := NewWebhookTaskHandlerWithClient(repo, &http.Client{})
	secret := "test-secret"

	data := []byte(`{"ip":"1.2.3.4"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedSignature, r.Header.Get("X-Blocklist-Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhooks := []models.OutboundWebhook{
		{
			ID:     123,
			URL:    server.URL,
			Secret: secret,
			Active: true,
		},
	}

	repo.On("GetActiveWebhooks").Return(webhooks, nil)
	repo.On("LogWebhookDelivery", mock.Anything).Return(nil)

	task, err := NewWebhookDeliveryTask(123, "ip.blocked", data)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	assert.NoError(t, err)

	repo.AssertExpectations(t)
}

func TestWebhookHMACSignature(t *testing.T) {
	secret := "my-secret-key"
	data := []byte(`{"test":"data"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	signature := hex.EncodeToString(mac.Sum(nil))

	// Verify signature is deterministic
	mac2 := hmac.New(sha256.New, []byte(secret))
	mac2.Write(data)
	signature2 := hex.EncodeToString(mac2.Sum(nil))

	assert.Equal(t, signature, signature2)
	assert.NotEmpty(t, signature)
	assert.Equal(t, 64, len(signature)) // SHA256 hex is 64 chars
}

func TestWebhookTaskHandler_NewHandler(t *testing.T) {
	// Test that we can create a handler without panicking
	handler := NewWebhookTaskHandler(nil)
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.client)
}
