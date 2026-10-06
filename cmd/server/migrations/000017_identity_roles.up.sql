-- Additive identity migration. Legacy permission snapshots remain authoritative
-- until an account is explicitly assigned a managed role.
CREATE TABLE access_roles (
    id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '',
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX access_roles_name_unique ON access_roles (lower(name));

INSERT INTO access_roles (id, name, description, permissions, is_builtin) VALUES
('viewer', 'Viewer', 'Read-only access across the workspace. Credentials remain protected.', 'gui_read,view_ips,view_stats,view_audit_logs,view_event_logs,view_whitelist,view_excluded,view_settings,view_admins,view_roles,view_api_tokens,export_data', TRUE),
('moderator', 'Moderator', 'View everything; create whitelist entries and exclusions; unblock addresses. No access administration.', 'gui_read,view_ips,view_stats,view_audit_logs,view_event_logs,view_whitelist,view_excluded,view_settings,view_admins,view_roles,view_api_tokens,export_data,whitelist_ips,exclude_ips,unblock_ips', TRUE),
('editor', 'Editor', 'Full workspace, configuration and access administration.', 'gui_read,view_ips,view_stats,view_audit_logs,view_event_logs,view_whitelist,view_excluded,view_settings,view_admins,view_roles,view_api_tokens,export_data,block_ips,unblock_ips,whitelist_ips,manage_whitelist,exclude_ips,manage_excluded,manage_views,manage_webhooks,manage_api_tokens,manage_global_tokens,manage_admins,manage_roles', TRUE);

ALTER TABLE admins ADD COLUMN role_id TEXT REFERENCES access_roles(id) ON DELETE RESTRICT;
ALTER TABLE admins ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'entra'));
ALTER TABLE admins ADD COLUMN entra_tenant_id UUID;
ALTER TABLE admins ADD COLUMN entra_object_id UUID;
ALTER TABLE admins ADD COLUMN entra_upn TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN entra_role_override BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE admins ADD CONSTRAINT admins_entra_binding_complete CHECK ((entra_tenant_id IS NULL) = (entra_object_id IS NULL));
CREATE UNIQUE INDEX admins_entra_identity_unique ON admins (entra_tenant_id, entra_object_id) WHERE entra_object_id IS NOT NULL;
-- UPN is display metadata only: it can change or be reassigned in Microsoft Entra.
CREATE INDEX admins_role_id_idx ON admins (role_id) WHERE role_id IS NOT NULL;
