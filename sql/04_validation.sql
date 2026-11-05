USE scamtrace;
-- Run after MySQL setup to inspect core table counts, constraints, and routines.
SELECT COUNT(*) AS core_table_count_expected_20 FROM information_schema.tables
WHERE table_schema=DATABASE() AND table_type='BASE TABLE';
SELECT COUNT(*) AS foreign_key_links_expected_22
FROM information_schema.key_column_usage
WHERE table_schema=DATABASE() AND referenced_table_name IS NOT NULL;
SELECT table_name,COUNT(*) AS fk_count
FROM information_schema.key_column_usage
WHERE table_schema=DATABASE() AND referenced_table_name IS NOT NULL
GROUP BY table_name ORDER BY table_name;
SELECT routine_name,routine_type FROM information_schema.routines
WHERE routine_schema=DATABASE() ORDER BY routine_name;
SELECT trigger_name,event_manipulation,event_object_table
FROM information_schema.triggers WHERE trigger_schema=DATABASE() ORDER BY trigger_name;
SELECT report_id,title,status FROM scam_report ORDER BY report_id LIMIT 12;
SELECT pattern_id,pattern_name,report_count FROM scam_pattern ORDER BY pattern_id;
SELECT fn_risk_level(91) AS expected_critical,fn_risk_level(17) AS expected_low;
