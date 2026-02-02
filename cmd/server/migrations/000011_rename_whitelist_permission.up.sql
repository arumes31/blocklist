-- Rename webhook_whitelist to whitelist_ips
UPDATE admins 
SET permissions = REPLACE(permissions, 'webhook_whitelist', 'whitelist_ips')
WHERE permissions LIKE '%webhook_whitelist%';

UPDATE api_tokens 
SET permissions = REPLACE(permissions, 'webhook_whitelist', 'whitelist_ips')
WHERE permissions LIKE '%webhook_whitelist%';
