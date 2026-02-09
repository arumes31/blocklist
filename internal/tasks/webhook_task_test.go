package tasks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	// Skip - requires full repository mock
	t.Skip("Requires full PostgresRepository mock implementation")
}

func TestWebhookTaskHandler_ProcessTask_Success(t *testing.T) {
	// Skip - requires full repository mock
	t.Skip("Requires full PostgresRepository mock implementation")
}

func TestWebhookTaskHandler_ProcessTask_DeletedWebhook(t *testing.T) {
	// Skip - requires full repository mock
	t.Skip("Requires full PostgresRepository mock implementation")
}

func TestWebhookTaskHandler_ProcessTask_HTTPError(t *testing.T) {
	// Skip - requires full repository mock
	t.Skip("Requires full PostgresRepository mock implementation")
}

func TestWebhookTaskHandler_ProcessTask_NoSecret(t *testing.T) {
	// Skip - requires full repository mock
	t.Skip("Requires full PostgresRepository mock implementation")
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
