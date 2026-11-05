-- Read-only checks against Review-1: 20 core tables and 22 foreign-key links.
-- Run after selecting the scamtrace database and applying 01_core_schema.sql.
USE scamtrace;

SELECT COUNT(*) AS core_table_count_expected_20
FROM information_schema.tables
WHERE table_schema=DATABASE() AND table_type='BASE TABLE';

SELECT COUNT(*) AS foreign_key_link_count_expected_22
FROM information_schema.key_column_usage
WHERE table_schema=DATABASE() AND referenced_table_name IS NOT NULL;

SELECT table_name,column_name,column_type
FROM information_schema.columns
WHERE table_schema=DATABASE()
  AND table_name IN ('user','scam_report','risk_analysis','moderation_action')
ORDER BY FIELD(table_name,'user','scam_report','risk_analysis','moderation_action'),ordinal_position;

SELECT COUNT(*) AS last_login_column_expected_1
FROM information_schema.columns
WHERE table_schema=DATABASE()
  AND table_name='user' AND column_name='last_login';

SELECT table_name,constraint_name,constraint_type
FROM information_schema.table_constraints
WHERE constraint_schema=DATABASE() AND constraint_type='CHECK'
ORDER BY table_name,constraint_name;
