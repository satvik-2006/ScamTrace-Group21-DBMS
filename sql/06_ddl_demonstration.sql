-- Optional DDL exercise in a separate schema; does not alter scamtrace.
-- Safe to rerun. This is not part of the 20-table ERD schema.
CREATE DATABASE IF NOT EXISTS scamtrace_ddl_lab CHARACTER SET utf8mb4;
USE scamtrace_ddl_lab;

CREATE TABLE IF NOT EXISTS ddl_demo_note (
    note_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    note_text VARCHAR(500) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (note_id)
) ENGINE=InnoDB;

-- ALTER example that is idempotent and only changes lab-table metadata.
ALTER TABLE ddl_demo_note COMMENT='Isolated ScamTrace DDL exercise';

SHOW CREATE TABLE ddl_demo_note;
