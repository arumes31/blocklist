package models

import (
	"fmt"
	"time"
)

const (
	MaxEventLogRetentionMonths = 3
	MaxAuditLogRetentionMonths = 12
)

// LogRetention separates enforcement history from system/security audit history.
type LogRetention struct {
	EventMonths int
	AuditMonths int
}

// DefaultLogRetention keeps the maximum allowed history for each category.
func DefaultLogRetention() LogRetention {
	return LogRetention{EventMonths: MaxEventLogRetentionMonths, AuditMonths: MaxAuditLogRetentionMonths}
}

// Validate rejects invalid or unlimited retention before a job can delete data.
func (p LogRetention) Validate() error {
	if p.EventMonths < 1 || p.EventMonths > MaxEventLogRetentionMonths {
		return fmt.Errorf("event log retention must be between 1 and %d months", MaxEventLogRetentionMonths)
	}
	if p.AuditMonths < 1 || p.AuditMonths > MaxAuditLogRetentionMonths {
		return fmt.Errorf("audit log retention must be between 1 and %d months", MaxAuditLogRetentionMonths)
	}
	return nil
}

// Cutoff subtracts calendar months in UTC, clamping to the target month's last
// day instead of letting time.AddDate normalize dates such as February 31.
func (p LogRetention) Cutoff(category string, now time.Time) (time.Time, error) {
	if err := p.Validate(); err != nil {
		return time.Time{}, err
	}
	var months int
	switch category {
	case "events":
		months = p.EventMonths
	case "system":
		months = p.AuditMonths
	default:
		return time.Time{}, fmt.Errorf("invalid log category %q", category)
	}
	now = now.UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -months, 0)
	day := min(now.Day(), month.AddDate(0, 1, -1).Day())
	return time.Date(month.Year(), month.Month(), day,
		now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), time.UTC), nil
}
