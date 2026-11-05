USE scamtrace;
-- ScamTrace: MySQL 8.0+ advanced DBMS features.
-- Apply after the 20-table DDL in 01_schema.sql inside the scamtrace database.
-- All statements below are MySQL syntax, not SQLite syntax.

-- Reconcile the original dump's stale zero pattern counts before adding triggers.
UPDATE scam_pattern AS p
SET report_count = (SELECT COUNT(*) FROM scam_report AS r WHERE r.pattern_id = p.pattern_id);

DROP FUNCTION IF EXISTS fn_risk_level;
DELIMITER $$
CREATE FUNCTION fn_risk_level(p_score DECIMAL(5,2))
RETURNS VARCHAR(20) DETERMINISTIC NO SQL
BEGIN
    IF p_score IS NULL THEN RETURN 'UNASSESSED';
    ELSEIF p_score >= 85 THEN RETURN 'CRITICAL';
    ELSEIF p_score >= 65 THEN RETURN 'HIGH';
    ELSEIF p_score >= 35 THEN RETURN 'MEDIUM';
    ELSE RETURN 'LOW';
    END IF;
END$$
DELIMITER ;

DROP PROCEDURE IF EXISTS sp_submit_scam_report;
DELIMITER $$
CREATE PROCEDURE sp_submit_scam_report(
    IN p_user_id INT UNSIGNED,
    IN p_category_id INT UNSIGNED,
    IN p_pattern_id INT UNSIGNED,
    IN p_title VARCHAR(200),
    IN p_description TEXT,
    IN p_source_type VARCHAR(50),
    IN p_risk_score DECIMAL(5,2),
    OUT p_report_id INT UNSIGNED
)
BEGIN
    DECLARE v_category_id INT UNSIGNED;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN ROLLBACK; RESIGNAL; END;
    IF p_title IS NULL OR CHAR_LENGTH(TRIM(p_title)) < 8
       OR p_description IS NULL OR CHAR_LENGTH(TRIM(p_description)) < 15
       OR p_risk_score IS NULL OR p_risk_score < 0 OR p_risk_score > 100 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Invalid report content or risk score';
    END IF;
    IF p_pattern_id IS NOT NULL THEN
        SET v_category_id = (SELECT category_id FROM scam_pattern WHERE pattern_id=p_pattern_id);
        IF v_category_id IS NULL OR v_category_id <> p_category_id THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Pattern does not belong to selected category';
        END IF;
    END IF;
    START TRANSACTION;
        INSERT INTO scam_report(user_id,category_id,pattern_id,title,description,source_type,risk_score,status)
        VALUES(p_user_id,p_category_id,p_pattern_id,TRIM(p_title),p_description,p_source_type,p_risk_score,'PENDING');
        SET p_report_id = LAST_INSERT_ID();
        INSERT INTO risk_analysis(report_id,risk_score,risk_level,model_version)
        VALUES(p_report_id,p_risk_score,fn_risk_level(p_risk_score),'sp-rules-v1');
    COMMIT;
END$$
DELIMITER ;

DROP PROCEDURE IF EXISTS sp_moderate_report;
DELIMITER $$
CREATE PROCEDURE sp_moderate_report(
    IN p_report_id INT UNSIGNED,
    IN p_moderator_id INT UNSIGNED,
    IN p_action VARCHAR(20),
    IN p_reason TEXT
)
BEGIN
    DECLARE v_status VARCHAR(20) DEFAULT NULL;
    DECLARE v_role VARCHAR(50) DEFAULT NULL;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN ROLLBACK; RESIGNAL; END;
    IF p_action NOT IN ('APPROVE','REJECT') OR p_action IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Invalid moderation action';
    END IF;
    SET v_role=(SELECT r.role_name FROM `user` u JOIN role r ON r.role_id=u.role_id WHERE u.user_id=p_moderator_id);
    IF v_role IS NULL OR v_role NOT IN ('ADMIN','MODERATOR') THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Moderator permission required';
    END IF;
    START TRANSACTION;
        SET v_status=(SELECT status FROM scam_report WHERE report_id=p_report_id FOR UPDATE);
        IF v_status IS NULL OR v_status <> 'PENDING' THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Report is not pending';
        END IF;
        UPDATE scam_report
        SET status=IF(p_action='APPROVE','VERIFIED','REJECTED') WHERE report_id=p_report_id;
        INSERT INTO moderation_action(report_id,moderator_id,action_type,reason)
        VALUES(p_report_id,p_moderator_id,p_action,p_reason);
        INSERT INTO audit_log(user_id,action,entity_type,entity_id)
        VALUES(p_moderator_id,p_action,'scam_report',p_report_id);
    COMMIT;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_report_before_insert;
DELIMITER $$
CREATE TRIGGER trg_report_before_insert
BEFORE INSERT ON scam_report FOR EACH ROW
BEGIN
    IF NEW.status NOT IN ('PENDING','VERIFIED','REJECTED') OR NEW.status IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Invalid report status';
    END IF;
    IF NEW.pattern_id IS NOT NULL AND
       NOT EXISTS (SELECT 1 FROM scam_pattern p WHERE p.pattern_id=NEW.pattern_id AND p.category_id=NEW.category_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Report category and pattern do not match';
    END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_report_before_update;
DELIMITER $$
CREATE TRIGGER trg_report_before_update
BEFORE UPDATE ON scam_report FOR EACH ROW
BEGIN
    IF NEW.status NOT IN ('PENDING','VERIFIED','REJECTED') OR NEW.status IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Invalid report status';
    END IF;
    IF OLD.status IN ('VERIFIED','REJECTED') AND NEW.status <> OLD.status THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Final moderation status cannot be reversed';
    END IF;
    IF NEW.pattern_id IS NOT NULL AND
       NOT EXISTS (SELECT 1 FROM scam_pattern p WHERE p.pattern_id=NEW.pattern_id AND p.category_id=NEW.category_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Report category and pattern do not match';
    END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_report_after_insert;
DELIMITER $$
CREATE TRIGGER trg_report_after_insert
AFTER INSERT ON scam_report FOR EACH ROW
BEGIN
    IF NEW.pattern_id IS NOT NULL THEN
        UPDATE scam_pattern SET report_count=report_count+1 WHERE pattern_id=NEW.pattern_id;
    END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_report_after_delete;
DELIMITER $$
CREATE TRIGGER trg_report_after_delete
AFTER DELETE ON scam_report FOR EACH ROW
BEGIN
    IF OLD.pattern_id IS NOT NULL THEN
        UPDATE scam_pattern SET report_count=GREATEST(0,report_count-1) WHERE pattern_id=OLD.pattern_id;
    END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_report_after_update;
DELIMITER $$
CREATE TRIGGER trg_report_after_update
AFTER UPDATE ON scam_report FOR EACH ROW
BEGIN
    IF NOT (OLD.pattern_id <=> NEW.pattern_id) THEN
        IF OLD.pattern_id IS NOT NULL THEN
            UPDATE scam_pattern SET report_count=GREATEST(0,report_count-1) WHERE pattern_id=OLD.pattern_id;
        END IF;
        IF NEW.pattern_id IS NOT NULL THEN
            UPDATE scam_pattern SET report_count=report_count+1 WHERE pattern_id=NEW.pattern_id;
        END IF;
    END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_moderation_permission;
DELIMITER $$
CREATE TRIGGER trg_moderation_permission
BEFORE INSERT ON moderation_action FOR EACH ROW
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM `user` AS u INNER JOIN role AS r ON r.role_id=u.role_id
        WHERE u.user_id=NEW.moderator_id AND r.role_name IN ('ADMIN','MODERATOR')
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Only moderators or admins may moderate';
    END IF;
END$$
DELIMITER ;

-- The view in the source dump joins ALL analyses (including multiple evaluations per
-- report). This replacement selects only the newest analysis to avoid duplicate rows.
DROP VIEW IF EXISTS vw_scam_report_analysis;
CREATE SQL SECURITY INVOKER VIEW vw_scam_report_analysis AS
SELECT sr.report_id,sr.title,sc.category_name,sr.risk_score AS report_risk_score,
       ra.risk_level,ra.model_version,ra.analyzed_at
FROM scam_report sr
JOIN scam_category sc ON sc.category_id=sr.category_id
LEFT JOIN risk_analysis ra ON ra.analysis_id=(
    SELECT MAX(ra2.analysis_id) FROM risk_analysis ra2 WHERE ra2.report_id=sr.report_id
);
