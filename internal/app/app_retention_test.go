package app

import (
	"testing"

	"blocklist/internal/config"
	"blocklist/internal/models"

	"github.com/stretchr/testify/require"
)

func TestBootstrapRejectsInvalidRetentionBeforeStorage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		policy models.LogRetention
	}{
		{"event exceeds three months", models.LogRetention{EventMonths: 4, AuditMonths: 12}},
		{"audit exceeds one year", models.LogRetention{EventMonths: 3, AuditMonths: 13}},
		{"audit cannot be unlimited", models.LogRetention{EventMonths: 3, AuditMonths: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			instance, err := Bootstrap(&config.Config{LogRetention: &tc.policy})
			require.Nil(t, instance)
			require.ErrorContains(t, err, "invalid log retention configuration")
		})
	}
}
