package service

import (
	"strconv"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestCalculateThreatScore(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	port, _ := strconv.Atoi(mr.Port())
	rRepo := repository.NewRedisRepository(mr.Host(), port, "", 0)
	cfg := &config.Config{}
	svc := NewIPService(cfg, rRepo, nil)

	tests := []struct {
		name     string
		ip       string
		reason   string
		banCount string
		expected int
	}{
		{
			name:     "Nil RedisRepo",
			ip:       "1.1.1.1",
			reason:   "some reason",
			expected: 0,
		},
		{
			name:     "Zero ban count, no keywords",
			ip:       "1.1.1.2",
			reason:   "generic activity",
			banCount: "0",
			expected: 0,
		},
		{
			name:     "Base score from bans",
			ip:       "1.1.1.3",
			reason:   "generic",
			banCount: "3",
			expected: 30,
		},
		{
			name:     "High severity bonus: brute force",
			ip:       "1.1.1.4",
			reason:   "SSH brute force",
			banCount: "0",
			expected: 20,
		},
		{
			name:     "Critical severity bonus: SQL injection",
			ip:       "1.1.1.5",
			reason:   "SQL injection attempt",
			banCount: "1",
			expected: 50, // 10 (base) + 40 (bonus)
		},
		{
			name:     "Spam bonus",
			ip:       "1.1.1.6",
			reason:   "Spamming email",
			banCount: "2",
			expected: 35, // 20 (base) + 15 (bonus)
		},
		{
			name:     "Scanner bonus",
			ip:       "1.1.1.7",
			reason:   "Port scanner detected",
			banCount: "0",
			expected: 10,
		},
		{
			name:     "Bot bonus",
			ip:       "1.1.1.8",
			reason:   "Malicious bot",
			banCount: "0",
			expected: 10,
		},
		{
			name:     "Keyword priority: brute vs sql",
			ip:       "1.1.1.9",
			reason:   "brute force sql injection",
			banCount: "0",
			expected: 20, // First match (brute) wins
		},
		{
			name:     "Case insensitivity",
			ip:       "1.1.1.10",
			reason:   "RCE ATTEMPT",
			banCount: "0",
			expected: 40,
		},
		{
			name:     "Cap at 100",
			ip:       "1.1.1.11",
			reason:   "SQL injection",
			banCount: "10",
			expected: 100, // 100 (base) + 40 (bonus) capped at 100
		},
		{
			name:     "Negative ban count handling",
			ip:       "1.1.1.12",
			reason:   "generic",
			banCount: "-5",
			expected: 0, // Capped at 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Nil RedisRepo" {
				nilSvc := &IPService{redisRepo: nil}
				score := nilSvc.CalculateThreatScore(tt.ip, tt.reason)
				assert.Equal(t, tt.expected, score)
				return
			}

			if tt.banCount != "" {
				mr.HSet("ips_ban_counts", tt.ip, tt.banCount)
			} else {
				mr.HDel("ips_ban_counts", tt.ip)
			}

			score := svc.CalculateThreatScore(tt.ip, tt.reason)
			assert.Equal(t, tt.expected, score)
		})
	}
}
