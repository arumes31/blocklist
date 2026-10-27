package service

import (
	"context"
	"strings"
	"sync"
	"time"

	zlog "github.com/rs/zerolog/log"
)

// AccountLabelSource lists sign-in names for Entra account keys, including keys
// of deleted accounts.
type AccountLabelSource interface {
	AccountLabels(ctx context.Context) (map[string]string, error)
}

const (
	accountLabelTTL         = 30 * time.Second
	accountLabelLoadTimeout = 3 * time.Second
)

// AccountLabels shows automatically provisioned Entra accounts by sign-in name
// instead of their entra:<tenant>:<object> key. Records keep the key, so a reused
// or renamed UPN never changes who a record belongs to; only account management
// shows the key itself.
type AccountLabels struct {
	source   AccountLabelSource
	mu       sync.Mutex
	current  *AccountLabelSet
	loadedAt time.Time
}

func NewAccountLabels(source AccountLabelSource) *AccountLabels {
	return &AccountLabels{source: source}
}

// Snapshot returns labels at most accountLabelTTL old. A failed reload keeps the
// previous snapshot and waits a full TTL before retrying. A nil receiver returns
// a nil set, which leaves every value unchanged.
func (a *AccountLabels) Snapshot(ctx context.Context) *AccountLabelSet {
	if a == nil || a.source == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.loadedAt.IsZero() && time.Since(a.loadedAt) < accountLabelTTL {
		return a.current
	}
	// One cancelled request must not fail the shared reload for other callers.
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), accountLabelLoadTimeout)
	defer cancel()
	labels, err := a.source.AccountLabels(loadCtx)
	a.loadedAt = time.Now()
	if err != nil {
		zlog.Warn().Err(err).Msg("Failed to load account labels; showing stored account keys")
		return a.current
	}
	a.current = newAccountLabelSet(labels)
	return a.current
}

// Invalidate makes the next Snapshot reload, such as after a first Entra sign-in.
func (a *AccountLabels) Invalidate() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.loadedAt = time.Time{}
	a.mu.Unlock()
}

// AccountLabelSet is an immutable label snapshot for one request or batch.
type AccountLabelSet struct {
	labels   map[string]string
	replacer *strings.Replacer
}

func newAccountLabelSet(labels map[string]string) *AccountLabelSet {
	pairs := make([]string, 0, len(labels)*2)
	for key, label := range labels {
		pairs = append(pairs, key, label)
	}
	return &AccountLabelSet{labels: labels, replacer: strings.NewReplacer(pairs...)}
}

// Label replaces each known account key in value, including keys inside composite
// values such as "key (203.0.113.7)" or "Webhook (key:203.0.113.7)". Unknown keys
// are left as stored.
func (s *AccountLabelSet) Label(value string) string {
	if s == nil || len(s.labels) == 0 || !strings.Contains(value, "entra:") {
		return value
	}
	return s.replacer.Replace(value)
}
