package service

import (
	"log"
	"os"

	"blocklist/internal/config"
	"blocklist/internal/tasks"

	"github.com/hibiken/asynq"
)

type GeoIPService struct {
	cfg         *config.Config
	asynqClient *asynq.Client
}

func NewGeoIPService(cfg *config.Config, redisOpts asynq.RedisClientOpt) *GeoIPService {
	return &GeoIPService{
		cfg:         cfg,
		asynqClient: asynq.NewClient(redisOpts),
	}
}

func (s *GeoIPService) Start() {
	// 1. Initial Check for both City and ASN
	for _, edition := range []string{"GeoLite2-City", "GeoLite2-ASN"} {
		dbPath := s.getDBPath(edition)
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			log.Printf("GeoIP %s database missing. Enqueuing initial download task...", edition)
			s.EnqueueUpdate(edition)
		}
	}

	// Note: Scheduled updates are now handled by asynq.Scheduler in main.go
}

func (s *GeoIPService) EnqueueUpdate(edition string) {
	task, err := tasks.NewGeoIPUpdateTask(edition)
	if err != nil {
		log.Printf("Error creating GeoIP task: %v", err)
		return
	}
	if _, err := s.asynqClient.Enqueue(task); err != nil {
		log.Printf("Error enqueuing GeoIP task: %v", err)
	}
}

func (s *GeoIPService) getDBPath(edition string) string {
	// Same path logic as tasks for consistency
	filename := edition + ".mmdb"
	path := "/home/blocklist/geoip/" + filename
	if _, err := os.Stat("/home/blocklist"); err != nil {
		path = "geoip_data/" + filename
	}
	return path
}

func (s *GeoIPService) Close() {
	if s.asynqClient != nil {
		_ = s.asynqClient.Close()
	}
}
