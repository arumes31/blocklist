CREATE TABLE IF NOT EXISTS external_sources (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'json_cidr', -- e.g., 'microsoft_365', 'json_cidr'
    refresh_interval_hours INT DEFAULT 6,
    failure_count INT DEFAULT 0,
    last_refresh_ts TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
