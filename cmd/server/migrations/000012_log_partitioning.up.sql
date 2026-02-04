-- Implement Declarative Partitioning for Logs

-- 1. Migrate audit_logs
-- Rename existing table to a temporary backup
ALTER TABLE audit_logs RENAME TO audit_logs_old;

-- Create new partitioned table (Note: partitioned tables cannot have serial PKs across partitions easily in older PG, 
-- but in modern PG we can use identity columns. However, the PK MUST include the partition key.)
CREATE TABLE audit_logs (
    id SERIAL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    actor TEXT,
    action TEXT,
    target TEXT,
    reason TEXT,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create initial partitions (Current and Next Month)
CREATE TABLE audit_logs_y2025m01 PARTITION OF audit_logs FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_logs_y2025m02 PARTITION OF audit_logs FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE audit_logs_y2025m03 PARTITION OF audit_logs FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE audit_logs_y2026m01 PARTITION OF audit_logs FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_logs_y2026m02 PARTITION OF audit_logs FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_logs_y2026m03 PARTITION OF audit_logs FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- Default partition for anything outside range
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

-- Copy old data into the new structure
INSERT INTO audit_logs (id, timestamp, actor, action, target, reason)
SELECT id, timestamp, actor, action, target, reason FROM audit_logs_old;

-- Drop old table
DROP TABLE audit_logs_old;


-- 2. Migrate webhook_logs
ALTER TABLE webhook_logs RENAME TO webhook_logs_old;

CREATE TABLE webhook_logs (
    id SERIAL,
    webhook_id INTEGER,
    event TEXT NOT NULL,
    payload TEXT NOT NULL,
    status_code INTEGER,
    response_body TEXT,
    error TEXT,
    attempt INTEGER DEFAULT 1,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Initial partitions
CREATE TABLE webhook_logs_y2025m01 PARTITION OF webhook_logs FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE webhook_logs_y2025m02 PARTITION OF webhook_logs FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE webhook_logs_y2025m03 PARTITION OF webhook_logs FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE webhook_logs_y2026m01 PARTITION OF webhook_logs FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE webhook_logs_y2026m02 PARTITION OF webhook_logs FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE webhook_logs_y2026m03 PARTITION OF webhook_logs FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE webhook_logs_default PARTITION OF webhook_logs DEFAULT;

INSERT INTO webhook_logs (id, webhook_id, event, payload, status_code, response_body, error, attempt, timestamp)
SELECT id, webhook_id, event, payload, status_code, response_body, error, attempt, timestamp FROM webhook_logs_old;

DROP TABLE webhook_logs_old;
