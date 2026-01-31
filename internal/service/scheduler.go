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
				s.redisRepo.ExecUnblockAtomic(ip)
			} else {
				s.redisRepo.HDel(hashKey, ip)
			}
			log.Printf("Deleted %s from %s (expired at %s)", ip, hashKey, expireTime.Format(time.RFC3339))
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
	// Rule for automate: newly added (last 1 min) or expiring soon (next 6 mins)
	// (Matching original Python logic roughly)

	for ip, jsonStr := range data {
		var entry struct {
			Timestamp string `json:"timestamp"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
			continue
		}

		startTime, _ := time.Parse("2006-01-02 15:04:05 UTC", entry.Timestamp)
		
		expireTime := time.Time{}
		if entry.ExpiresAt != "" {
			expireTime, _ = time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
		} else if !startTime.IsZero() {
			expireTime = startTime.Add(24 * time.Hour)
		}

		if startTime.IsZero() || expireTime.IsZero() { continue }

		// newly added
		if now.Sub(startTime) <= 1*time.Minute {
			filteredIPs = append(filteredIPs, ip)
			continue
		}

		// expiring soon
		if expireTime.Sub(now) <= 6*time.Minute {
			filteredIPs = append(filteredIPs, ip)
		}
	}
	s.redisRepo.SetCache("cached_ips_automate", filteredIPs, 5*time.Minute)
}
