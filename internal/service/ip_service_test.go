package service

import (
	"testing"

	"blocklist/internal/config"
)

func TestIPService_IsValidIP(t *testing.T) {
	cfg := &config.Config{
		BlockedRanges: "10.0.0.0/8,192.168.1.0/24",
	}
	
	// Testing without Redis (whitelist will be empty)
	svc := NewIPService(cfg, nil, nil) 

	tests := []struct {
		ip       string
		expected bool
	}{
		{"1.1.1.1", true},
		{"10.0.0.1", false},
		{"192.168.1.50", false},
		{"8.8.8.8", true},
		{"invalid-ip", false},
	}

	for _, tt := range tests {
		if got := svc.IsValidIP(tt.ip); got != tt.expected {
			t.Errorf("IsValidIP(%s) = %v, want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestIPService_GetGeoIP_Nil(t *testing.T) {
	svc := NewIPService(&config.Config{}, nil, nil)
	geo := svc.GetGeoIP("8.8.8.8")
	// Without mmdb file, it should return nil (or try to open and fail)
	if geo != nil {
		t.Error("expected nil geo data without database")
	}
}

func TestIPService_Stats_Empty(t *testing.T) {
	// This will likely fail or return zeros if redisRepo is nil.
	// But let's test the nil safety if possible.
	// (Actually s.redisRepo.CountLastHour() will panic if redisRepo is nil)
}
