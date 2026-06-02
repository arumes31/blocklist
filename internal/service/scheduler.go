package service

import (
	"blocklist/internal/config"
	"blocklist/internal/repository"
	"context"
	"encoding/json"
	"sync"
	"time"

	zlog "github.com/rs/zerolog/log"
)

type SchedulerService struct {
	redisRepo *repository.RedisRepository
	pgRepo    *repository.PostgresRepository
	cfg       *config.Config
	ipService *IPService
	stop      chan struct{}
	stopOnce  sync.Once
}

// SetIPService attaches an IPService so the scheduler can run excluded-list FQDN
// pre-resolution. Optional; resolution is skipped when nil.
func (s *SchedulerService) SetIPService(svc *IPService) {
	s.ipService = svc
}

func NewSchedulerService(r *repository.RedisRepository, p *repository.PostgresRepository, cfg *config.Config) *SchedulerService {
	return &SchedulerService{
		redisRepo: r,
		pgRepo:    p,
		cfg:       cfg,
		stop:      make(chan struct{}),
	}
}

func (s *SchedulerService) Start() {
	// Warm the local FQDN-exclusion cache once at startup so the first block
	// check after boot does not pay a DNS round-trip.
	if s.ipService != nil {
		go s.ipService.RefreshExcludedFQDNs(context.Background())
	}

	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				token, acquired, err := s.redisRepo.AcquireLock("lock_cleanup", 10*time.Minute)
				if err != nil {
					zlog.Error().Err(err).Msg("Error acquiring cleanup lock")
					continue
				}
				if acquired {
					s.CleanOldIPs("ips")
					s.CleanOldIPs("ips_webhook2_whitelist")
					s.CleanOldIPs("ips_webhook2_excluded")

					// Refresh excluded FQDN resolutions (and surface failures).
					if s.ipService != nil {
						s.ipService.RefreshExcludedFQDNs(context.Background())
					}

					if s.pgRepo != nil {
						zlog.Info().Msg("Managing database partitions")
						retention := 6
						if s.cfg != nil && s.cfg.LogRetentionMonths > 0 {
							retention = s.cfg.LogRetentionMonths
						}
						if err := s.pgRepo.EnsurePartitions(retention); err != nil {
							zlog.Error().Err(err).Msg("Error ensuring partitions")
						}
					}

					if err := s.redisRepo.ReleaseLock("lock_cleanup", token); err != nil {
						zlog.Error().Err(err).Str("token", token).Msg("Error releasing cleanup lock")
					}
				}
			case <-s.stop:
				return
			}
		}
	}()
}

func (s *SchedulerService) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
}

func (s *SchedulerService) CleanOldIPs(hashKey string) {
	if s.redisRepo == nil {
		return
	}
	data, err := s.redisRepo.HGetAllRaw(hashKey)
	if err != nil {
		zlog.Error().Err(err).Str("hashKey", hashKey).Msg("Error fetching hash for cleanup")
		return
	}

	now := time.Now().UTC()

	for ip, jsonStr := range data {
		var entry struct {
			Timestamp string `json:"timestamp"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
			continue
		}

		expireTime := time.Time{}
		if entry.ExpiresAt != "" {
			var err error
			expireTime, err = time.Parse(time.RFC3339, entry.ExpiresAt)
			if err != nil {
				expireTime, _ = time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
			}
		}
		// No fallback: if ExpiresAt is empty, the entry never expires (e.g. permanent whitelists)

		if !expireTime.IsZero() && now.After(expireTime) {
			if hashKey == "ips" {
				// Atomically remove from hash and ZSET
				if err := s.redisRepo.ExecUnblockAtomic(ip); err != nil {
					zlog.Error().Err(err).Str("ip", ip).Msg("Error during atomic unblock")
				}
			} else {
				if err := s.redisRepo.HDel(hashKey, ip); err != nil {
					zlog.Error().Err(err).Str("ip", ip).Str("hashKey", hashKey).Msg("Error deleting IP from hash")
				}
			}
			zlog.Info().Str("ip", ip).Str("hashKey", hashKey).Time("expiredAt", expireTime).Msg("Deleted expired IP")
		}
	}
}
