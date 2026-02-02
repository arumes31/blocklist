-- Rename whitelist_ips back to webhook_whitelist
UPDATE admins 
SET permissions = REPLACE(permissions, 'whitelist_ips', 'webhook_whitelist')
WHERE permissions LIKE '%whitelist_ips%';

UPDATE api_tokens 
SET permissions = REPLACE(permissions, 'whitelist_ips', 'webhook_whitelist')
WHERE permissions LIKE '%whitelist_ips%';
