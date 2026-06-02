package tasks

import (
	"context"
	"fmt"

	"github.com/hibiken/asynq"
)

const (
	TypeRefreshExternalSources = "refresh:external_sources"
)

type ExternalSourceRefresher interface {
	RefreshAll(ctx context.Context)
}

type ExternalSourceTaskHandler struct {
	svc ExternalSourceRefresher
}

func NewExternalSourceTaskHandler(svc ExternalSourceRefresher) *ExternalSourceTaskHandler {
	return &ExternalSourceTaskHandler{svc: svc}
}

func (h *ExternalSourceTaskHandler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	switch t.Type() {
	case TypeRefreshExternalSources:
		h.svc.RefreshAll(ctx)
		return nil
	default:
		return fmt.Errorf("unexpected task type: %s", t.Type())
	}
}

func NewRefreshExternalSourcesTask() *asynq.Task {
	return asynq.NewTask(TypeRefreshExternalSources, nil)
}
