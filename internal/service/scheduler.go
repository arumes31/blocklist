package service

import (
	"blocklist/internal/repository"
	"encoding/json"
	"log"
	"time"
)

type SchedulerService struct {
	redisRepo *repository.RedisRepository
}

func NewSchedulerService(r *repository.RedisRepository) *SchedulerService {
	return &SchedulerService{redisRepo: r}
}

func (s *SchedulerService) Start() {
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		for range ticker.C {
			if acquired, _ := s.redisRepo.AcquireLock("lock_cleanup", 10*time.Minute); acquired {
				s.CleanOldIPs("ips")
				s.CleanOldIPs("ips_webhook2_whitelist")
				_ = s.redisRepo.ReleaseLock("lock_cleanup")
			}
		}
	}()
}

func (s *SchedulerService) CleanOldIPs(hashKey string) {
	if s.redisRepo == nil { return }
	data, err := s.redisRepo.HGetAllRaw(hashKey)
	if err != nil {
		log.Printf("Error fetching %s for cleanup: %v", hashKey, err)
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
			expireTime, _ = time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
		} else if entry.Timestamp != "" {
			// Fallback to 24h from timestamp
			t, _ := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
			if !t.IsZero() {
				expireTime = t.Add(24 * time.Hour)
			}
		}

		if !expireTime.IsZero() && now.After(expireTime) {
			if hashKey == "ips" {
				// Atomically remove from hash and ZSET
				if err := s.redisRepo.ExecUnblockAtomic(ip); err != nil {
					log.Printf("Error during atomic unblock of %s: %v", ip, err)
				}
			} else {
				if err := s.redisRepo.HDel(hashKey, ip); err != nil {
					log.Printf("Error deleting %s from %s: %v", ip, hashKey, err)
				}
			}
			log.Printf("Deleted %s from %s (expired at %s)", ip, hashKey, expireTime.Format(time.RFC3339))
		}
	}
}
