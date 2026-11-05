-- Optional MySQL 8.0+ partitioning lab.
-- Creates an isolated schema and synthetic rows; it never changes or copies scamtrace data.
CREATE DATABASE IF NOT EXISTS scamtrace_partition_lab CHARACTER SET utf8mb4;
USE scamtrace_partition_lab;

CREATE TABLE IF NOT EXISTS audit_log_partition_demo (
    sample_key VARCHAR(64) NOT NULL,
    event_at DATETIME NOT NULL,
    actor_label VARCHAR(40) NOT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    PRIMARY KEY (sample_key,event_at),
    KEY idx_event_at (event_at)
) ENGINE=InnoDB
PARTITION BY RANGE COLUMNS(event_at) (
    PARTITION p_before_2025 VALUES LESS THAN ('2025-01-01 00:00:00'),
    PARTITION p2025 VALUES LESS THAN ('2026-01-01 00:00:00'),
    PARTITION p2026 VALUES LESS THAN ('2027-01-01 00:00:00'),
    PARTITION p_future VALUES LESS THAN (MAXVALUE)
);

-- Synthetic sample records only. INSERT IGNORE keeps repeated runs idempotent.
INSERT IGNORE INTO audit_log_partition_demo
    (sample_key,event_at,actor_label,action,entity_type)
VALUES
    ('synthetic-2025-a','2025-03-15 10:00:00','demo-user','CREATE','scam_report'),
    ('synthetic-2026-a','2026-06-20 14:30:00','demo-moderator','APPROVE','scam_report'),
    ('synthetic-2027-a','2027-02-01 08:00:00','demo-user','SEARCH','indicator');

-- Inspect selected partitions; the date predicate should prune unrelated ranges.
EXPLAIN PARTITIONS
SELECT sample_key,event_at,action
FROM audit_log_partition_demo
WHERE event_at >= '2026-01-01 00:00:00'
  AND event_at <  '2027-01-01 00:00:00';

SELECT partition_name,table_rows
FROM information_schema.partitions
WHERE table_schema=DATABASE()
  AND table_name='audit_log_partition_demo'
ORDER BY partition_ordinal_position;
