package models

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeEntraUPN(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value, expected string
	}{
		{name: "normal", value: "person@example.com", expected: "person@example.com"},
		{name: "case and outer whitespace", value: " Person@Example.com ", expected: "person@example.com"},
		{name: "guest upn", value: "person_example.com#EXT#@tenant.onmicrosoft.com", expected: "person_example.com#ext#@tenant.onmicrosoft.com"},
		{name: "empty"},
		{name: "missing domain", value: "person@"},
		{name: "missing at", value: "person"},
		{name: "display name", value: "Person <person@example.com>"},
		{name: "comment", value: "person@example.com (Person)"},
		{name: "quoted local part", value: "\"person\"@example.com"},
		{name: "list", value: "one@example.com,two@example.com"},
		{name: "internal whitespace", value: "per son@example.com"},
		{name: "unicode whitespace", value: "per\u2003son@example.com"},
		{name: "control", value: "person\x00@example.com"},
		{name: "too long", value: strings.Repeat("p", 245) + "@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeEntraUPN(tc.value)
			if tc.expected == "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestPermissionCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, permission := range PermissionCatalog {
		require.False(t, seen[permission.Key], permission.Key)
		seen[permission.Key] = true
		require.NotEmpty(t, permission.Description)
	}
	got, err := NormalizePermissions("view_ips, gui_read,view_ips")
	require.NoError(t, err)
	require.Equal(t, "gui_read,view_ips", got)
	_, err = NormalizePermissions("superuser")
	require.Error(t, err)
	require.False(t, HasPermission("preview_ips", "view_ips"))
	require.Equal(t, "view_ips", IntersectPermissions("view_ips,block_ips", "view_ips"))
}

func TestLogCategoriesFailTowardSystem(t *testing.T) {
	for _, action := range []string{"BLOCK", "UNBLOCK", "WHITELIST", "EXCLUDE"} {
		require.True(t, IsEventAction(action), action)
	}
	for _, action := range []string{"LOGIN_SUCCESS", "CREATE_ROLE", "UPDATE_TOKEN_PERMISSIONS", "FUTURE_ACTION", ""} {
		require.False(t, IsEventAction(action), action)
	}
}
