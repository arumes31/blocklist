package service

import (
	"testing"

	"blocklist/internal/config"
	"github.com/hibiken/asynq"
)

func TestGeoIPService_Start(t *testing.T) {
	svc := NewGeoIPService(&config.Config{}, asynq.RedisClientOpt{})
	svc.Start()
}
