-- Add outbound_webhooks table

CREATE TABLE IF NOT EXISTS outbound_webhooks (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    events TEXT NOT NULL, -- comma-separated events (block, unblock)
    secret TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webhook_logs (
    id SERIAL PRIMARY KEY,
    webhook_id INTEGER REFERENCES outbound_webhooks(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    payload TEXT NOT NULL,
    status_code INTEGER,
    response_body TEXT,
    error TEXT,
    attempt INTEGER DEFAULT 1,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
