-- Update existing admin user with expanded granular permissions (webhook_access omitted by default)
UPDATE admins SET permissions = 'view_ips,view_stats,export_data,manage_whitelist,manage_webhooks,manage_api_tokens,manage_global_tokens,manage_admins,webhook_ban,webhook_unban,webhook_whitelist' WHERE username = 'admin';
