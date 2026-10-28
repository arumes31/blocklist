package tasks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"blocklist/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestWebhookDefaultClientDoesNotFollowRedirects(t *testing.T) {
	handler := NewWebhookTaskHandler(nil)
	require.NotNil(t, handler.client.CheckRedirect)
	assert.True(t, errors.Is(handler.client.CheckRedirect(nil, nil), http.ErrUseLastResponse))
}

func TestWebhookRedirectResponseIsNotADelivery(t *testing.T) {
	repo := new(mockWebhookRepository)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/hook")
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	defer server.Close()
	client := newTestClient(server)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	handler := NewWebhookTaskHandlerWithClient(repo, client)
	repo.On("GetWebhookByID", 8).Return(&models.OutboundWebhook{ID: 8, URL: "http://example.com/hook", Active: true}, nil)
	repo.On("LogWebhookDelivery", mock.Anything).Return(nil)

	task, err := NewWebhookDeliveryTask(8, "ip.blocked", []byte(`{}`))
	require.NoError(t, err)
	assert.Error(t, handler.ProcessTask(context.Background(), task), "an unfollowed 3xx must be retried, not dropped")
}

func TestWebhookSignatureV2CoversTimestamp(t *testing.T) {
	repo := new(mockWebhookRepository)
	secret := "test-secret"
	data := []byte(`{"ip":"192.0.2.1"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestamp := r.Header.Get("X-Blocklist-Timestamp")
		assert.NotEmpty(t, timestamp)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(timestamp + "."))
		mac.Write(data)
		assert.Equal(t, hex.EncodeToString(mac.Sum(nil)), r.Header.Get("X-Blocklist-Signature-V2"))
		assert.NotEmpty(t, r.Header.Get("X-Blocklist-Signature"), "legacy signature is kept")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewWebhookTaskHandlerWithClient(repo, newTestClient(server))
	repo.On("GetWebhookByID", 7).Return(&models.OutboundWebhook{ID: 7, URL: "http://example.com/hook", Secret: secret, Active: true}, nil)
	repo.On("LogWebhookDelivery", mock.Anything).Return(nil)

	task, err := NewWebhookDeliveryTask(7, "ip.blocked", data)
	require.NoError(t, err)
	require.NoError(t, handler.ProcessTask(context.Background(), task))
	repo.AssertExpectations(t)
}
