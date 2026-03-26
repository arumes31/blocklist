package service

import (
	"blocklist/internal/config"
	"blocklist/internal/repository"
	"encoding/json"
	"time"

	zlog "github.com/rs/zerolog/log"
)

type SchedulerService struct {
	redisRepo *repository.RedisRepository
	pgRepo    *repository.PostgresRepository
	cfg       *config.Config
}

func NewSchedulerService(r *repository.RedisRepository, p *repository.PostgresRepository, cfg *config.Config) *SchedulerService {
	return &SchedulerService{redisRepo: r, pgRepo: p, cfg: cfg}
}

func (s *SchedulerService) Start() {
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		for range ticker.C {
			token, acquired, err := s.redisRepo.AcquireLock("lock_cleanup", 10*time.Minute)
			if err != nil {
				zlog.Error().Err(err).Msg("Error acquiring cleanup lock")
				continue
			}
			if acquired {
				s.CleanOldIPs("ips")
				s.CleanOldIPs("ips_webhook2_whitelist")

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
		}
	}()
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
