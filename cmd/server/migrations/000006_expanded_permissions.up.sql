-- Update existing admin user with expanded granular permissions (webhook_access omitted by default)
UPDATE admins SET permissions = 'view_ips,view_stats,export_data,manage_whitelist,manage_webhooks,manage_api_tokens,manage_global_tokens,manage_admins,block_ips,unblock_ips,whitelist_ips' WHERE username = 'admin';
