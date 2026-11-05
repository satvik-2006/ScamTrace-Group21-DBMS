-- DBMS mini-project query demonstrations; use on MySQL 8 after import + routines.
USE scamtrace;

-- Q1: Simple SELECT, GROUP BY, aggregate COUNT/AVG, and HAVING.
SELECT c.category_name,COUNT(r.report_id) AS total_reports,
       ROUND(AVG(r.risk_score),2) AS average_risk
FROM scam_category c
LEFT JOIN scam_report r ON r.category_id=c.category_id
GROUP BY c.category_id,c.category_name
HAVING COUNT(r.report_id)>0
ORDER BY total_reports DESC;

-- Q2: UPDATE operation, demonstrated without permanently modifying the database.
START TRANSACTION;
SET @target_report_id=(SELECT report_id FROM scam_report
                       WHERE status='PENDING' ORDER BY report_id LIMIT 1);
UPDATE scam_report SET risk_score=LEAST(100,risk_score+2)
WHERE report_id=@target_report_id AND status='PENDING';
SELECT report_id,risk_score,status FROM scam_report WHERE report_id=@target_report_id;
ROLLBACK;

-- Q3: DELETE operation; temporary row and rollback keep source data intact.
START TRANSACTION;
SET @sample_report_id=(SELECT report_id FROM scam_report ORDER BY report_id LIMIT 1);
SELECT LAST_INSERT_ID(0) INTO @temporary_evidence_id;
INSERT INTO evidence(report_id,evidence_type,description)
SELECT @sample_report_id,'TEXT_NOTE','Transaction demo: temporary note'
WHERE @sample_report_id IS NOT NULL;
SET @temporary_evidence_id=LAST_INSERT_ID();
DELETE FROM evidence WHERE evidence_id=@temporary_evidence_id AND @temporary_evidence_id<>0;
SELECT COUNT(*) AS remaining_demo_rows FROM evidence
WHERE evidence_id=@temporary_evidence_id;
ROLLBACK;

-- Q4: Correlated query: risk higher than the average risk in the SAME category.
SELECT r.report_id,r.title,r.risk_score,c.category_name
FROM scam_report r JOIN scam_category c ON c.category_id=r.category_id
WHERE r.risk_score > (
    SELECT AVG(r2.risk_score) FROM scam_report r2
    WHERE r2.category_id=r.category_id
)
ORDER BY r.risk_score DESC;

-- Q5: Nested query: reports that match HIGH / CRITICAL patterns.
SELECT r.report_id,r.title,r.status
FROM scam_report r
WHERE r.pattern_id IN (
    SELECT p.pattern_id FROM scam_pattern p
    WHERE p.risk_level IN ('HIGH','CRITICAL')
)
ORDER BY r.report_id;

-- Q6: Multi-table JOIN - report, reporter, pattern, and category.
SELECT r.report_id,r.title,u.name AS reporter,c.category_name,p.pattern_name,r.status
FROM scam_report r
JOIN `user` u ON u.user_id=r.user_id
JOIN scam_category c ON c.category_id=r.category_id
LEFT JOIN scam_pattern p ON p.pattern_id=r.pattern_id
ORDER BY r.report_id LIMIT 20;

-- Q7: A report lookup across the many-to-many URL junction table.
SELECT r.report_id,r.title,ind.url,ind.domain
FROM scam_report r
JOIN report_url ru ON ru.report_id=r.report_id
JOIN url ind ON ind.url_id=ru.url_id
WHERE r.status='VERIFIED';

-- Q8: Anti-join - scam patterns with no linked reports.
SELECT p.pattern_id,p.pattern_name
FROM scam_pattern p
WHERE NOT EXISTS (SELECT 1 FROM scam_report r WHERE r.pattern_id=p.pattern_id);

-- Q9: Function demonstration.
SELECT report_id,title,risk_score,fn_risk_level(risk_score) AS risk_level
FROM scam_report ORDER BY risk_score DESC LIMIT 10;

-- Q10: View demonstration - latest risk analysis per report.
SELECT * FROM vw_scam_report_analysis ORDER BY report_id;

-- Procedure usage (commented to prevent accidental creation / moderation):
-- CALL sp_submit_scam_report(3,1,1,'Example KYC phishing incident',
--   'Suspicious urgent KYC verification link sent by SMS', 'SMS', 80.00, @new_report_id);
-- SELECT @new_report_id;
-- CALL sp_moderate_report(@new_report_id,2,'APPROVE','Checked evidence');
