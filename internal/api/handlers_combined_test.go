package api

import (
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAPIHandler_getCombinedIPs(t *testing.T) {
	t.Run("NoPostgres", func(t *testing.T) {
		h, rRepo, _, _, _ := setupTest()
		h.pgRepo = nil // Ensure pgRepo is nil

		redisIPs := map[string]models.IPEntry{
			"1.1.1.1": {Reason: "redis block"},
		}
		rRepo.On("GetBlockedIPs").Return(redisIPs, nil)

		ips := h.getCombinedIPs()

		assert.Len(t, ips, 1)
		assert.Equal(t, "redis block", ips["1.1.1.1"].Reason)
		rRepo.AssertExpectations(t)
	})

	t.Run("CacheHit", func(t *testing.T) {
		h, rRepo, pgRepo, _, _ := setupTest()

		redisIPs := map[string]models.IPEntry{
			"1.1.1.1": {Reason: "redis block"},
		}
		cachedIPs := map[string]models.IPEntry{
			"2.2.2.2": {Reason: "persistent block cached"},
		}

		rRepo.On("GetBlockedIPs").Return(redisIPs, nil)
		rRepo.On("GetCache", "persistent_ips_cache", mock.Anything).Run(func(args mock.Arguments) {
			target := args.Get(1).(*map[string]models.IPEntry)
			*target = cachedIPs
		}).Return(nil)

		ips := h.getCombinedIPs()

		assert.Len(t, ips, 2)
		assert.Equal(t, "redis block", ips["1.1.1.1"].Reason)
		assert.Equal(t, "persistent block cached", ips["2.2.2.2"].Reason)

		// Ensure pgRepo was not called
		pgRepo.AssertNotCalled(t, "GetPersistentBlocks")
		rRepo.AssertExpectations(t)
	})

	t.Run("CacheMiss", func(t *testing.T) {
		h, rRepo, pgRepo, _, _ := setupTest()

		redisIPs := map[string]models.IPEntry{
			"1.1.1.1": {Reason: "redis block"},
		}
		persistentIPs := map[string]models.IPEntry{
			"3.3.3.3": {Reason: "persistent block db"},
		}

		rRepo.On("GetBlockedIPs").Return(redisIPs, nil)
		rRepo.On("GetCache", "persistent_ips_cache", mock.Anything).Return(assert.AnError)
		pgRepo.On("GetPersistentBlocks").Return(persistentIPs, nil)
		rRepo.On("SetCache", "persistent_ips_cache", persistentIPs, 1*time.Minute).Return(nil)

		ips := h.getCombinedIPs()

		assert.Len(t, ips, 2)
		assert.Equal(t, "redis block", ips["1.1.1.1"].Reason)
		assert.Equal(t, "persistent block db", ips["3.3.3.3"].Reason)

		rRepo.AssertExpectations(t)
		pgRepo.AssertExpectations(t)
	})

	t.Run("MergeLogic", func(t *testing.T) {
		h, rRepo, pgRepo, _, _ := setupTest()

		redisIPs := map[string]models.IPEntry{
			"1.1.1.1": {Reason: "redis block"},
			"4.4.4.4": {Reason: "redis block overlap"},
		}
		persistentIPs := map[string]models.IPEntry{
			"4.4.4.4": {Reason: "persistent block overlap"},
			"5.5.5.5": {Reason: "persistent block unique"},
		}

		rRepo.On("GetBlockedIPs").Return(redisIPs, nil)
		rRepo.On("GetCache", "persistent_ips_cache", mock.Anything).Return(assert.AnError)
		pgRepo.On("GetPersistentBlocks").Return(persistentIPs, nil)
		rRepo.On("SetCache", "persistent_ips_cache", persistentIPs, 1*time.Minute).Return(nil)

		ips := h.getCombinedIPs()

		assert.Len(t, ips, 3)
		assert.Equal(t, "redis block", ips["1.1.1.1"].Reason)
		assert.Equal(t, "persistent block overlap", ips["4.4.4.4"].Reason) // Persistent should overwrite Redis in current implementation
		assert.Equal(t, "persistent block unique", ips["5.5.5.5"].Reason)

		rRepo.AssertExpectations(t)
		pgRepo.AssertExpectations(t)
	})
}
