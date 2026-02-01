-- Update existing admin user with expanded granular permissions (webhook_access omitted by default)
UPDATE admins SET permissions = 'view_ips,view_stats,export_data,block_ips,unblock_ips,manage_whitelist,manage_webhooks,manage_api_tokens,manage_admins' WHERE username = 'admin';
