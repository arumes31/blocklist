package app

import (
	"blocklist/internal/config"
	"blocklist/internal/repository"
	"blocklist/internal/service"
	"context"
	"fmt"

	"github.com/hibiken/asynq"
)

type App struct {
	Config         *config.Config
	RedisRepo      *repository.RedisRepository
	PgRepo         *repository.PostgresRepository
	AuthService    *service.AuthService
	IPService      *service.IPService
	WebhookService *service.WebhookService
	GeoUpdater     *service.GeoIPService
	Scheduler      *service.SchedulerService
	RedisOpts      asynq.RedisClientOpt
}

func Bootstrap(cfg *config.Config) (*App, error) {
	// Initialize Repositories
	redisRepo := repository.NewRedisRepository(cfg.RedisHost, cfg.RedisPort, cfg.RedisPassword, cfg.RedisDB)
	if err := redisRepo.GetClient().Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	pgRepo, err := repository.NewPostgresRepository(cfg.PostgresURL, cfg.PostgresReadURL, cfg.AuditLogLimitPerIP)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Postgres: %w", err)
	}

	// Initialize Services
	authService := service.NewAuthService(pgRepo, redisRepo)
	ipService := service.NewIPService(cfg, redisRepo, pgRepo)

	redisOpts := asynq.RedisClientOpt{
		Addr:     fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}

	webhookService := service.NewWebhookService(pgRepo, cfg, redisOpts)
	geoUpdater := service.NewGeoIPService(cfg, redisOpts)
	scheduler := service.NewSchedulerService(redisRepo, pgRepo, cfg)

	return &App{
		Config:         cfg,
		RedisRepo:      redisRepo,
		PgRepo:         pgRepo,
		AuthService:    authService,
		IPService:      ipService,
		WebhookService: webhookService,
		GeoUpdater:     geoUpdater,
		Scheduler:      scheduler,
		RedisOpts:      redisOpts,
	}, nil
}

func (a *App) Close() {
	if a.WebhookService != nil {
		a.WebhookService.Close()
	}
	if a.GeoUpdater != nil {
		a.GeoUpdater.Close()
	}
}
