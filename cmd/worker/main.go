package main

import (
	"blocklist/internal/app"
	"blocklist/internal/config"
	"blocklist/internal/tasks"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func main() {
	// Setup Logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

	cfg := config.Load()
	if cfg.LogWeb {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	zlog.Info().Msg("Starting Blocklist Standalone Worker")

	// Bootstrap shared dependencies
	a, err := app.Bootstrap(cfg)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to bootstrap app")
	}
	defer a.Close()

	// Initialize Asynq Server
	asynqServer := asynq.NewServer(
		a.RedisOpts,
		asynq.Config{
			Concurrency: 20, // Dedicated worker can have higher concurrency
			Queues: map[string]int{
				"default": 5,
				"low":     2,
			},
		},
	)

	asynqMux := asynq.NewServeMux()
	asynqMux.Handle(tasks.TypeWebhookDelivery, tasks.NewWebhookTaskHandler(a.PgRepo))
	asynqMux.Handle(tasks.TypeGeoIPUpdate, tasks.NewGeoIPTaskHandler(cfg, a.IPService))

	// Run worker
	go func() {
		if err := asynqServer.Run(asynqMux); err != nil {
			zlog.Fatal().Err(err).Msg("Failed to run asynq server")
		}
	}()

	// Wait for interrupt
	zlog.Info().Msg("Worker running. Press Ctrl+C to exit.")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zlog.Info().Msg("Shutting down worker...")
	asynqServer.Shutdown()
	zlog.Info().Msg("Worker exited")
}
