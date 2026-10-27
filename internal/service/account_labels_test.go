package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testEntraKey   = "entra:36c0ac06-6d8c-45b3-8a7f-9f7bb48e20f5:26854b10-125c-4d3b-9085-95a8b753f152"
	testOtherKey   = "entra:36c0ac06-6d8c-45b3-8a7f-9f7bb48e20f5:8fc1addd-0bea-4672-ba1e-37bc2899e67d"
	testUnknownKey = "entra:36c0ac06-6d8c-45b3-8a7f-9f7bb48e20f5:b647d650-3f1c-48ca-920e-6a957707e803"
)

type fakeAccountLabelSource struct {
	mu     sync.Mutex
	labels map[string]string
	err    error
	calls  int
}

func (f *fakeAccountLabelSource) AccountLabels(ctx context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	labels := make(map[string]string, len(f.labels))
	for key, label := range f.labels {
		labels[key] = label
	}
	return labels, nil
}

func TestAccountLabelSetLabel(t *testing.T) {
	labels := newAccountLabelSet(map[string]string{
		testEntraKey: "Editor@Example.test",
		testOtherKey: "moderator@example.test",
	})
	for _, tc := range []struct{ name, value, want string }{
		{name: "account key", value: testEntraKey, want: "Editor@Example.test"},
		{name: "block actor with address", value: testEntraKey + " (203.0.113.7)", want: "Editor@Example.test (203.0.113.7)"},
		{name: "webhook actor", value: "Webhook (" + testOtherKey + ":198.51.100.2)", want: "Webhook (moderator@example.test:198.51.100.2)"},
		{name: "local account", value: "operator", want: "operator"},
		{name: "unknown key stays stored", value: testUnknownKey, want: testUnknownKey},
		{name: "empty", value: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, labels.Label(tc.value))
		})
	}
	var missing *AccountLabelSet
	require.Equal(t, testEntraKey, missing.Label(testEntraKey), "a nil set must leave values unchanged")
	require.Equal(t, testEntraKey, newAccountLabelSet(nil).Label(testEntraKey))
}

func TestAccountLabelsSnapshotCachesAndInvalidates(t *testing.T) {
	source := &fakeAccountLabelSource{labels: map[string]string{testEntraKey: "editor@example.test"}}
	labels := NewAccountLabels(source)

	require.Equal(t, "editor@example.test", labels.Snapshot(t.Context()).Label(testEntraKey))
	source.labels[testOtherKey] = "moderator@example.test"
	require.Equal(t, testOtherKey, labels.Snapshot(t.Context()).Label(testOtherKey), "within the TTL the snapshot is reused")
	require.Equal(t, 1, source.calls)

	labels.Invalidate()
	require.Equal(t, "moderator@example.test", labels.Snapshot(t.Context()).Label(testOtherKey))
	require.Equal(t, 2, source.calls)

	labels.loadedAt = time.Now().Add(-accountLabelTTL)
	labels.Snapshot(t.Context())
	require.Equal(t, 3, source.calls, "an expired snapshot reloads")
}

func TestAccountLabelsSnapshotFailures(t *testing.T) {
	t.Run("keeps last good labels without retrying until the TTL expires", func(t *testing.T) {
		source := &fakeAccountLabelSource{labels: map[string]string{testEntraKey: "editor@example.test"}}
		labels := NewAccountLabels(source)
		labels.Snapshot(t.Context())
		source.err = errors.New("database unavailable")
		labels.Invalidate()
		require.Equal(t, "editor@example.test", labels.Snapshot(t.Context()).Label(testEntraKey))
		labels.Snapshot(t.Context())
		require.Equal(t, 2, source.calls)
	})
	t.Run("a first failure shows stored keys", func(t *testing.T) {
		source := &fakeAccountLabelSource{err: errors.New("database unavailable")}
		labels := NewAccountLabels(source)
		require.Equal(t, testEntraKey, labels.Snapshot(t.Context()).Label(testEntraKey))
		labels.Snapshot(t.Context())
		require.Equal(t, 1, source.calls)
	})
	t.Run("a cancelled request still loads shared labels", func(t *testing.T) {
		source := &fakeAccountLabelSource{labels: map[string]string{testEntraKey: "editor@example.test"}}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.Equal(t, "editor@example.test", NewAccountLabels(source).Snapshot(ctx).Label(testEntraKey))
	})
	t.Run("nil labels are inert", func(t *testing.T) {
		var labels *AccountLabels
		labels.Invalidate()
		require.Nil(t, labels.Snapshot(t.Context()))
		require.Nil(t, NewAccountLabels(nil).Snapshot(t.Context()))
	})
}
