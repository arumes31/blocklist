package config

import (
	"testing"

	"blocklist/internal/models"

	"github.com/stretchr/testify/require"
)

func TestLoadLogRetention(t *testing.T) {
	for _, tc := range []struct {
		name, event, audit string
		want               models.LogRetention
		invalid            bool
	}{
		{name: "defaults", want: models.DefaultLogRetention()},
		{name: "independent windows", event: "2", audit: "9", want: models.LogRetention{EventMonths: 2, AuditMonths: 9}},
		{name: "minimum", event: "1", audit: "1", want: models.LogRetention{EventMonths: 1, AuditMonths: 1}},
		{name: "trim whitespace", event: " 3 ", audit: " 12 ", want: models.DefaultLogRetention()},
		{name: "event over maximum", event: "4", invalid: true},
		{name: "audit over maximum", audit: "13", invalid: true},
		{name: "zero not unlimited", audit: "0", invalid: true},
		{name: "negative not unlimited", event: "-1", invalid: true},
		{name: "noninteger", audit: "year", invalid: true},
		{name: "overflow", audit: "999999999999999999999", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("EVENT_LOG_RETENTION_MONTHS", tc.event)
			t.Setenv("AUDIT_LOG_RETENTION_MONTHS", tc.audit)
			t.Setenv("LOG_RETENTION_MONTHS", "1")
			cfg := Load()
			policy := cfg.LogRetentionPolicy()
			if tc.invalid {
				require.Error(t, policy.Validate())
			} else {
				require.NoError(t, policy.Validate())
				require.Equal(t, tc.want, policy)
			}
			require.Equal(t, 1, cfg.LogRetentionMonths, "webhook retention stays separate")
		})
	}
	require.Equal(t, models.DefaultLogRetention(), (&Config{}).LogRetentionPolicy())
}
