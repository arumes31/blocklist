package service

import (
	"strconv"
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/repository"

	"github.com/alicebob/miniredis/v2"
)

func TestCalculateThreatScore_Comprehensive(t *testing.T) {
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
		noRepo   bool
	}{
		{
			name:     "Redis repo is nil",
			ip:       "1.1.1.1",
			reason:   "SSH brute force",
			expected: 0,
			noRepo:   true,
		},
		{
			name:     "No prior bans, no severity bonus",
			ip:       "1.1.1.1",
			reason:   "Generic reason",
			banCount: "0",
			expected: 0,
		},
		{
			name:     "SSH bonus",
			ip:       "1.1.1.1",
			reason:   "SSH brute force",
			banCount: "0",
			expected: 20,
		},
		{
			name:     "Brute bonus",
			ip:       "1.1.1.1",
			reason:   "Brute force attempt",
			banCount: "0",
			expected: 20,
		},
		{
			name:     "Login bonus",
			ip:       "1.1.1.1",
			reason:   "Login failure",
			banCount: "0",
			expected: 20,
		},
		{
			name:     "SQL bonus",
			ip:       "1.1.1.1",
			reason:   "SQL injection attempt",
			banCount: "0",
			expected: 40,
		},
		{
			name:     "Inject bonus",
			ip:       "1.1.1.1",
			reason:   "Malicious Inject",
			banCount: "0",
			expected: 40,
		},
		{
			name:     "RCE bonus",
			ip:       "1.1.1.1",
			reason:   "RCE exploit",
			banCount: "0",
			expected: 40,
		},
		{
			name:     "Spam bonus",
			ip:       "1.1.1.1",
			reason:   "Spam bot",
			banCount: "0",
			expected: 15,
		},
		{
			name:     "Scanner bonus",
			ip:       "1.1.1.1",
			reason:   "Port Scanner",
			banCount: "0",
			expected: 10,
		},
		{
			name:     "Bot bonus",
			ip:       "1.1.1.1",
			reason:   "Search bot (malicious)",
			banCount: "0",
			expected: 10,
		},
		{
			name:     "Base score from ban count (2 bans)",
			ip:       "1.1.1.1",
			reason:   "generic",
			banCount: "2",
			expected: 20,
		},
		{
			name:     "Base score + SQL bonus (2 bans + 40)",
			ip:       "1.1.1.1",
			reason:   "SQL injection",
			banCount: "2",
			expected: 60,
		},
		{
			name:     "Cap at 100",
			ip:       "1.1.1.1",
			reason:   "SQL injection",
			banCount: "10",
			expected: 100, // 100 + 40 -> 100
		},
		{
			name:     "Floor at 0",
			ip:       "1.1.1.1",
			reason:   "generic",
			banCount: "-5",
			expected: 0, // -50 -> 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var currentSvc *IPService
			if tt.noRepo {
				currentSvc = &IPService{redisRepo: nil}
			} else {
				currentSvc = svc
				mr.HSet("ips_ban_counts", tt.ip, tt.banCount)
			}

			score := currentSvc.CalculateThreatScore(tt.ip, tt.reason)
			if score != tt.expected {
				t.Errorf("expected score %d, got %d", tt.expected, score)
			}
		})
	}
}
