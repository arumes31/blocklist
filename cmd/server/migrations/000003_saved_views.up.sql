-- Add saved_views table

CREATE TABLE IF NOT EXISTS saved_views (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
    name TEXT NOT NULL,
    filters TEXT NOT NULL, -- Store as JSON string
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_saved_views_username ON saved_views(username);
