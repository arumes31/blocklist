package models

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdminAccountDisplayName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source, upn, want string
	}{
		{name: "entra", source: "entra", upn: "person@example.test", want: "person@example.test"},
		{
			name: "trimmed entra upn", source: "entra",
			upn: " Person@Example.test ", want: "Person@Example.test",
		},
		{name: "missing entra upn", source: "entra", want: "stable-key"},
		{name: "blank entra upn", source: "entra", upn: "  ", want: "stable-key"},
		{name: "local ignores upn", source: "local", upn: "person@example.test", want: "stable-key"},
		{name: "legacy local", upn: "person@example.test", want: "stable-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			account := AdminAccount{Username: "stable-key", AuthSource: tc.source, EntraUPN: tc.upn}
			before := account
			if got := account.DisplayName(); got != tc.want {
				t.Errorf("DisplayName() = %q, want %q", got, tc.want)
			}
			if account != before {
				t.Fatal("display label changed the stored identity")
			}
		})
	}
}

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

func TestPermissionsCoverAccount(t *testing.T) {
	t.Parallel()
	role := "custom"
	for _, tc := range []struct {
		name        string
		account     AdminAccount
		permissions string
		allowed     bool
	}{
		{
			name: "legacy retired keys", account: AdminAccount{Permissions: "gui_read, gui_write,webhook_access,"},
			permissions: "gui_read", allowed: true,
		},
		{
			name: "local legacy retired keys", account: AdminAccount{AuthSource: "local", Permissions: "gui_write,webhook_access"},
			allowed: true,
		},
		{
			name: "live permissions still required", account: AdminAccount{Permissions: "gui_write,manage_roles"},
			permissions: "gui_read,manage_admins",
		},
		{
			name: "workspace aliases still required", account: AdminAccount{Permissions: "view_ips"},
			permissions: "view_ips",
		},
		{
			name: "editor covers legacy aliases", account: AdminAccount{Permissions: "view_ips,gui_write"},
			permissions: AllPermissions(), allowed: true,
		},
		{
			name: "unknown key fails closed", account: AdminAccount{Permissions: "unknown"},
			permissions: AllPermissions(),
		},
		{
			name: "managed role is explicit", account: AdminAccount{RoleID: &role, Permissions: "gui_write"},
			permissions: AllPermissions(),
		},
		{
			name: "Entra is explicit", account: AdminAccount{AuthSource: "entra", Permissions: "webhook_access"},
			permissions: AllPermissions(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := tc.account
			require.Equal(t, tc.allowed, PermissionsCoverAccount(tc.permissions, tc.account))
			require.Equal(t, before, tc.account, "stored permissions must not be rewritten")
		})
	}
}

func TestLogCategoriesFailTowardSystem(t *testing.T) {
	for _, action := range []string{"BLOCK", "UNBLOCK", "WHITELIST", "EXCLUDE"} {
		require.True(t, IsEventAction(action), action)
	}
	for _, action := range []string{"LOGIN_SUCCESS", "CREATE_ROLE", "UPDATE_TOKEN_PERMISSIONS", "FUTURE_ACTION", ""} {
		require.False(t, IsEventAction(action), action)
	}
}
