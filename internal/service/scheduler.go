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
				s.redisRepo.ReleaseLock("lock_cleanup")
			}
		}
	}()

	// Cache updater for ips_automate
	cacheTicker := time.NewTicker(30 * time.Second)
	go func() {
		for range cacheTicker.C {
			if acquired, _ := s.redisRepo.AcquireLock("lock_ips_automate_update", 25*time.Second); acquired {
				s.UpdateAutomateCache()
				s.redisRepo.ReleaseLock("lock_ips_automate_update")
			}
		}
	}()
}

func (s *SchedulerService) CleanOldIPs(hashKey string) {
	data, err := s.redisRepo.HGetAllRaw(hashKey)
	if err != nil {
		log.Printf("Error fetching %s for cleanup: %v", hashKey, err)
		return
	}

	now := time.Now().UTC()
	threshold := now.Add(-24 * time.Hour)

	for ip, jsonStr := range data {
		var entry struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
			continue
		}

		// Parse "2026-01-31 17:00:00 UTC"
		t, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
		if err != nil {
			continue
		}

		if t.Before(threshold) {
			if hashKey == "ips" {
				// Atomically remove from hash and ZSET
				s.redisRepo.ExecUnblockAtomic(ip)
			} else {
				s.redisRepo.HDel(hashKey, ip)
			}
			log.Printf("Deleted %s from %s (added at %s)", ip, hashKey, entry.Timestamp)
		}
	}
}

func (s *SchedulerService) UpdateAutomateCache() {
	data, err := s.redisRepo.HGetAllRaw("ips")
	if err != nil {
		return
	}

	now := time.Now().UTC()
	filteredIPs := []string{}
	deltaHigh := 24*time.Hour + 1*time.Minute
	deltaLow := 23*time.Hour + 54*time.Minute

	for ip, jsonStr := range data {
		var entry struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
			continue
		}

		t, err := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
		if err != nil {
			continue
		}

		expireTime := t.Add(24 * time.Hour)
		remaining := expireTime.Sub(now)

		if remaining >= deltaHigh || remaining <= deltaLow {
			filteredIPs = append(filteredIPs, ip)
		}
	}
	s.redisRepo.SetCache("cached_ips_automate", filteredIPs, 5*time.Minute)
}
