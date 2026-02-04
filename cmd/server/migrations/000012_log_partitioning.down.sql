-- Revert partitioning

-- 1. Revert audit_logs
CREATE TABLE audit_logs_new (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    actor TEXT,
    action TEXT,
    target TEXT,
    reason TEXT
);

INSERT INTO audit_logs_new (id, timestamp, actor, action, target, reason)
SELECT id, timestamp, actor, action, target, reason FROM audit_logs;

DROP TABLE audit_logs;
ALTER TABLE audit_logs_new RENAME TO audit_logs;


-- 2. Revert webhook_logs
CREATE TABLE webhook_logs_new (
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

INSERT INTO webhook_logs_new (id, webhook_id, event, payload, status_code, response_body, error, attempt, timestamp)
SELECT id, webhook_id, event, payload, status_code, response_body, error, attempt, timestamp FROM webhook_logs;

DROP TABLE webhook_logs;
ALTER TABLE webhook_logs_new RENAME TO webhook_logs;
