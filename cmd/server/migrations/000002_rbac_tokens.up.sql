-- Add RBAC roles and API tokens table

ALTER TABLE admins ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'operator';

-- Update main admin to be admin
-- Note: We don't know the main admin username here easily, 
-- but we can set a default and let the app handle it on start.

CREATE TABLE IF NOT EXISTS api_tokens (
    id SERIAL PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
