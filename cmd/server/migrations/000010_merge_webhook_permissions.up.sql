-- Merge webhook_ban into block_ips and webhook_unban into unblock_ips
-- Then deduplicate the permissions list

-- Update admins table
UPDATE admins 
SET permissions = (
    SELECT string_agg(DISTINCT trim(p), ',')
    FROM unnest(string_to_array(
        REPLACE(
            REPLACE(permissions, 'webhook_ban', 'block_ips'),
            'webhook_unban', 'unblock_ips'
        ), 
        ','
    )) AS p
)
WHERE permissions LIKE '%webhook_ban%' OR permissions LIKE '%webhook_unban%';

-- Update api_tokens table
UPDATE api_tokens 
SET permissions = (
    SELECT string_agg(DISTINCT trim(p), ',')
    FROM unnest(string_to_array(
        REPLACE(
            REPLACE(permissions, 'webhook_ban', 'block_ips'),
            'webhook_unban', 'unblock_ips'
        ), 
        ','
    )) AS p
)
WHERE permissions LIKE '%webhook_ban%' OR permissions LIKE '%webhook_unban%';
