package models

import (
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"unicode"
)

// Permission describes a server-enforced capability shown in the role editor.
type Permission struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Group       string `json:"group"`
	Description string `json:"description"`
}

var PermissionCatalog = []Permission{
	{Key: "gui_read", Label: "Open workspace", Group: "Read", Description: "Sign in and use the web interface."},
	{Key: "view_ips", Label: "IP records and threat map", Group: "Read", Description: "Read blocked addresses and their history."},
	{Key: "view_stats", Label: "Statistics", Group: "Read", Description: "Read aggregate activity and trends."},
	{Key: "view_audit_logs", Label: "System audit logs", Group: "Read", Description: "Read authentication, access and configuration activity."},
	{Key: "view_event_logs", Label: "Event logs", Group: "Read", Description: "Read blocking, whitelist and exclusion activity."},
	{Key: "view_whitelist", Label: "Whitelist", Group: "Read", Description: "Read whitelist entries."},
	{Key: "view_excluded", Label: "Exclusions", Group: "Read", Description: "Read exclusions and external sources."},
	{Key: "view_settings", Label: "Settings", Group: "Read", Description: "Read integration settings without revealing secrets."},
	{Key: "view_admins", Label: "Accounts", Group: "Read", Description: "Read account metadata, never passwords or MFA secrets."},
	{Key: "view_roles", Label: "Roles", Group: "Read", Description: "Read roles and their permissions."},
	{Key: "view_api_tokens", Label: "API access", Group: "Read", Description: "Read token metadata, never raw token values."},
	{Key: "export_data", Label: "Export records", Group: "Read", Description: "Download IP data after identity verification."},
	{Key: "block_ips", Label: "Block addresses", Group: "Enforcement", Description: "Create individual and bulk blocks."},
	{Key: "unblock_ips", Label: "Unblock addresses", Group: "Enforcement", Description: "Remove individual and bulk blocks."},
	{Key: "whitelist_ips", Label: "Create whitelist entries", Group: "Enforcement", Description: "Add whitelist entries without deleting existing entries."},
	{Key: "manage_whitelist", Label: "Manage whitelist", Group: "Enforcement", Description: "Add and remove whitelist entries."},
	{Key: "exclude_ips", Label: "Create exclusions", Group: "Enforcement", Description: "Add IP, subnet or domain exclusions."},
	{Key: "manage_excluded", Label: "Manage exclusions and sources", Group: "Enforcement", Description: "Add/remove exclusions and configure or refresh external sources."},
	{Key: "manage_views", Label: "Save dashboard views", Group: "Workspace", Description: "Create and delete personal saved filters."},
	{Key: "manage_webhooks", Label: "Manage webhooks", Group: "Configuration", Description: "Create and remove outbound integrations."},
	{Key: "manage_api_tokens", Label: "Manage own API tokens", Group: "Access", Description: "Create, update and revoke personal tokens within current permissions."},
	{Key: "manage_global_tokens", Label: "Revoke any API token", Group: "Access", Description: "Revoke tokens belonging to other accounts."},
	{Key: "manage_admins", Label: "Manage accounts", Group: "Access", Description: "Create, delete and manage accounts and role assignments."},
	{Key: "manage_roles", Label: "Manage roles", Group: "Access", Description: "Create, update and delete role definitions."},
}

type AccessRole struct {
	ID          string `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	Description string `json:"description" db:"description"`
	Permissions string `json:"permissions" db:"permissions"`
	IsBuiltin   bool   `json:"is_builtin" db:"is_builtin"`
	Revision    int    `json:"revision" db:"revision"`
	MemberCount int    `json:"member_count" db:"member_count"`
}

type EntraIdentity struct {
	TenantID string
	ObjectID string
	UPN      string
	RoleID   string
}

// NormalizeEntraUPN validates a single sign-in name for an unbound invitation.
// Once bound, the tenant/object pair, not this mutable name, identifies an account.
func NormalizeEntraUPN(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	invalidLength := len(value) == 0 || len(value) > 255
	invalidCharacters := strings.ContainsAny(value, "<>\"") || strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0
	if invalidLength || invalidCharacters {
		return "", errors.New("invalid entra upn")
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return "", errors.New("invalid entra upn")
	}
	return value, nil
}

func HasPermission(permissions, key string) bool {
	for _, permission := range strings.Split(permissions, ",") {
		if strings.TrimSpace(permission) == key {
			return true
		}
	}
	return false
}

// WorkspacePermissions preserves the old view_ips capabilities for local
// accounts that still use individual permissions. Managed roles stay explicit.
// Use only for browser access; API-token scopes must never gain these aliases.
func WorkspacePermissions(account AdminAccount) string {
	permissions := account.Permissions
	local := account.AuthSource == "" || account.AuthSource == "local"
	if !local || account.RoleID != nil || !HasPermission(permissions, "view_ips") {
		return permissions
	}
	for _, permission := range []string{"view_audit_logs", "view_event_logs", "manage_views"} {
		if !HasPermission(permissions, permission) {
			permissions += "," + permission
		}
	}
	return permissions
}

func AllPermissions() string {
	keys := make([]string, 0, len(PermissionCatalog))
	for _, permission := range PermissionCatalog {
		keys = append(keys, permission.Key)
	}
	return strings.Join(keys, ",")
}

func NormalizePermissions(value string) (string, error) {
	keys := []string{}
	for _, key := range strings.Split(value, ",") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if !HasPermission(AllPermissions(), key) {
			return "", fmt.Errorf("unknown permission %q", key)
		}
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return strings.Join(keys, ","), nil
}

// IntersectPermissions ensures a token can never exceed its owner's current rights.
func IntersectPermissions(tokenPermissions, ownerPermissions string) string {
	keys := []string{}
	for _, key := range strings.Split(tokenPermissions, ",") {
		key = strings.TrimSpace(key)
		if key != "" && HasPermission(ownerPermissions, key) {
			keys = append(keys, key)
		}
	}
	return strings.Join(keys, ",")
}

var EventActions = []string{
	"BLOCK", "BULK_BLOCK", "BLOCK_PERSISTENT", "BLOCK_EPHEMERAL", "UNBLOCK",
	"WHITELIST", "UNWHITELIST", "EXCLUDE", "UNEXCLUDE",
}

func IsEventAction(action string) bool {
	return slices.Contains(EventActions, action)
}

type LogFilter struct {
	Category string
	Actor    string
	Action   string
	Query    string
	Limit    int
	Offset   int
}
