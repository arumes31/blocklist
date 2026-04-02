package repository

import (
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisRepository_Buckets(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	port, _ := strconv.Atoi(mr.Port())
	repo := NewRedisRepository(mr.Host(), port, "", 0)

	now := time.Now().UTC()
	hourKey := "stats:hour:" + now.Format("2006010215")
	dayKey := "stats:day:" + now.Format("20060102")

	t.Run("IncrHourBucket", func(t *testing.T) {
		err := repo.IncrHourBucket(now, 5)
		if err != nil {
			t.Fatalf("IncrHourBucket failed: %v", err)
		}

		// Verify hour bucket
		val, _ := mr.Get(hourKey)
		if val != "5" {
			t.Errorf("expected hour bucket value 5, got %s", val)
		}

		// Verify total ever
		total, _ := mr.Get("stats:total_ever")
		if total != "5" {
			t.Errorf("expected total_ever 5, got %s", total)
		}

		// Increment again
		_ = repo.IncrHourBucket(now, 10)
		val, _ = mr.Get(hourKey)
		if val != "15" {
			t.Errorf("expected hour bucket value 15, got %s", val)
		}
		total, _ = mr.Get("stats:total_ever")
		if total != "15" {
			t.Errorf("expected total_ever 15, got %s", total)
		}
	})

	t.Run("IncrDayBucket", func(t *testing.T) {
		err := repo.IncrDayBucket(now, 3)
		if err != nil {
			t.Fatalf("IncrDayBucket failed: %v", err)
		}

		// Verify day bucket
		val, _ := mr.Get(dayKey)
		if val != "3" {
			t.Errorf("expected day bucket value 3, got %s", val)
		}

		// Increment again
		_ = repo.IncrDayBucket(now, 7)
		val, _ = mr.Get(dayKey)
		if val != "10" {
			t.Errorf("expected day bucket value 10, got %s", val)
		}
	})

	t.Run("CountFunctions", func(t *testing.T) {
		// Reset for clean testing
		mr.FlushAll()

		// Before any increments
		cHour, _ := repo.CountLastHour()
		if cHour != 0 {
			t.Errorf("expected 0, got %d", cHour)
		}
		cDay, _ := repo.CountLastDay()
		if cDay != 0 {
			t.Errorf("expected 0, got %d", cDay)
		}
		cTotal, _ := repo.CountTotalEver()
		if cTotal != 0 {
			t.Errorf("expected 0, got %d", cTotal)
		}

		// Increment and verify
		_ = repo.IncrHourBucket(now, 100)
		_ = repo.IncrDayBucket(now, 200)

		cHour, _ = repo.CountLastHour()
		if cHour != 100 {
			t.Errorf("expected 100, got %d", cHour)
		}
		cDay, _ = repo.CountLastDay()
		if cDay != 200 {
			t.Errorf("expected 200, got %d", cDay)
		}
		cTotal, _ = repo.CountTotalEver()
		if cTotal != 100 { // total_ever is only incremented by IncrHourBucket in the current implementation
			t.Errorf("expected 100, got %d", cTotal)
		}
	})
}
