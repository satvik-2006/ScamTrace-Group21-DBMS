-- ScamTrace core schema (MySQL 8.0+).
-- DDL only: 20 ERD tables, 22 foreign keys, and no sample rows or DROP statements.
-- Apply to a new/empty scamtrace database. Existing tables are left untouched.

CREATE TABLE `role` (
  `role_id` int unsigned NOT NULL AUTO_INCREMENT,
  `role_name` varchar(50) NOT NULL,
  PRIMARY KEY (`role_id`),
  UNIQUE KEY `uq_role_name` (`role_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `user` (
  `user_id` int unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `phone` varchar(25) DEFAULT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role_id` int unsigned NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `uq_user_email` (`email`),
  KEY `fk_user_role` (`role_id`),
  CONSTRAINT `fk_user_role` FOREIGN KEY (`role_id`) REFERENCES `role` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `scam_category` (
  `category_id` int unsigned NOT NULL AUTO_INCREMENT,
  `category_name` varchar(100) NOT NULL,
  `description` text,
  PRIMARY KEY (`category_id`),
  UNIQUE KEY `uq_category_name` (`category_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `scam_pattern` (
  `pattern_id` int unsigned NOT NULL AUTO_INCREMENT,
  `category_id` int unsigned NOT NULL,
  `pattern_name` varchar(150) NOT NULL,
  `description` text,
  `risk_level` varchar(20) DEFAULT NULL,
  `first_detected` date DEFAULT NULL,
  `report_count` int unsigned NOT NULL DEFAULT '0',
  `status` varchar(20) NOT NULL DEFAULT 'ACTIVE',
  PRIMARY KEY (`pattern_id`),
  KEY `fk_pattern_category` (`category_id`),
  CONSTRAINT `fk_pattern_category` FOREIGN KEY (`category_id`) REFERENCES `scam_category` (`category_id`),
  CONSTRAINT `chk_report_count` CHECK ((`report_count` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `scam_report` (
  `report_id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `category_id` int unsigned NOT NULL,
  `pattern_id` int unsigned DEFAULT NULL,
  `title` varchar(200) NOT NULL,
  `description` text,
  `source_type` varchar(50) DEFAULT NULL,
  `reported_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `risk_score` decimal(5,2) DEFAULT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'PENDING',
  PRIMARY KEY (`report_id`),
  KEY `fk_report_user` (`user_id`),
  KEY `fk_report_category` (`category_id`),
  KEY `fk_report_pattern` (`pattern_id`),
  KEY `idx_report_status` (`status`),
  CONSTRAINT `fk_report_category` FOREIGN KEY (`category_id`) REFERENCES `scam_category` (`category_id`),
  CONSTRAINT `fk_report_pattern` FOREIGN KEY (`pattern_id`) REFERENCES `scam_pattern` (`pattern_id`),
  CONSTRAINT `fk_report_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`),
  CONSTRAINT `chk_risk_score` CHECK ((`risk_score` between 0 and 100))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `risk_factor` (
  `factor_id` int unsigned NOT NULL AUTO_INCREMENT,
  `factor_name` varchar(150) NOT NULL,
  `description` text,
  `weight` decimal(5,2) DEFAULT NULL,
  PRIMARY KEY (`factor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `risk_analysis` (
  `analysis_id` int unsigned NOT NULL AUTO_INCREMENT,
  `report_id` int unsigned NOT NULL,
  `risk_score` decimal(5,2) DEFAULT NULL,
  `risk_level` varchar(20) DEFAULT NULL,
  `model_version` varchar(30) DEFAULT NULL,
  `analyzed_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`analysis_id`),
  KEY `fk_analysis_report` (`report_id`),
  CONSTRAINT `fk_analysis_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `analysis_risk_factor` (
  `analysis_id` int unsigned NOT NULL,
  `factor_id` int unsigned NOT NULL,
  `contribution_score` decimal(5,2) DEFAULT NULL,
  `detected` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`analysis_id`,`factor_id`),
  KEY `fk_arf_factor` (`factor_id`),
  CONSTRAINT `fk_arf_analysis` FOREIGN KEY (`analysis_id`) REFERENCES `risk_analysis` (`analysis_id`),
  CONSTRAINT `fk_arf_factor` FOREIGN KEY (`factor_id`) REFERENCES `risk_factor` (`factor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `moderation_action` (
  `action_id` int unsigned NOT NULL AUTO_INCREMENT,
  `report_id` int unsigned NOT NULL,
  `moderator_id` int unsigned NOT NULL,
  `action_type` varchar(50) DEFAULT NULL,
  `reason` text,
  `action_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`action_id`),
  KEY `fk_moderation_report` (`report_id`),
  KEY `fk_moderation_moderator` (`moderator_id`),
  CONSTRAINT `fk_moderation_moderator` FOREIGN KEY (`moderator_id`) REFERENCES `user` (`user_id`),
  CONSTRAINT `fk_moderation_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `audit_log` (
  `audit_id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `action` varchar(100) DEFAULT NULL,
  `entity_type` varchar(50) DEFAULT NULL,
  `entity_id` int unsigned DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`audit_id`),
  KEY `fk_audit_user` (`user_id`),
  CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `evidence` (
  `evidence_id` int unsigned NOT NULL AUTO_INCREMENT,
  `report_id` int unsigned NOT NULL,
  `evidence_type` varchar(50) DEFAULT NULL,
  `file_path` varchar(500) DEFAULT NULL,
  `description` text,
  `uploaded_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`evidence_id`),
  KEY `fk_evidence_report` (`report_id`),
  CONSTRAINT `fk_evidence_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `report_confirmation` (
  `confirmation_id` int unsigned NOT NULL AUTO_INCREMENT,
  `report_id` int unsigned NOT NULL,
  `user_id` int unsigned NOT NULL,
  `confirmation_type` varchar(30) DEFAULT NULL,
  `comment` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`confirmation_id`),
  UNIQUE KEY `uq_confirmation_report_user` (`report_id`,`user_id`),
  KEY `fk_confirmation_user` (`user_id`),
  CONSTRAINT `fk_confirmation_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`),
  CONSTRAINT `fk_confirmation_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `phone_number` (
  `phone_id` int unsigned NOT NULL AUTO_INCREMENT,
  `phone_number` varchar(20) NOT NULL,
  `reputation_score` decimal(5,2) DEFAULT NULL,
  `total_reports` int unsigned NOT NULL DEFAULT '0',
  `status` varchar(20) NOT NULL DEFAULT 'UNVERIFIED',
  PRIMARY KEY (`phone_id`),
  UNIQUE KEY `uq_phone_number` (`phone_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `email_address` (
  `email_id` int unsigned NOT NULL AUTO_INCREMENT,
  `email_address` varchar(150) NOT NULL,
  `domain` varchar(100) DEFAULT NULL,
  `reputation_score` decimal(5,2) DEFAULT NULL,
  `total_reports` int unsigned NOT NULL DEFAULT '0',
  `status` varchar(20) NOT NULL DEFAULT 'UNVERIFIED',
  PRIMARY KEY (`email_id`),
  UNIQUE KEY `uq_email_address` (`email_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `url` (
  `url_id` int unsigned NOT NULL AUTO_INCREMENT,
  `url` varchar(500) NOT NULL,
  `domain` varchar(150) DEFAULT NULL,
  `reputation_score` decimal(5,2) DEFAULT NULL,
  `total_reports` int unsigned NOT NULL DEFAULT '0',
  `status` varchar(20) NOT NULL DEFAULT 'UNVERIFIED',
  PRIMARY KEY (`url_id`),
  UNIQUE KEY `uq_url` (`url`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `upi_id` (
  `upi_id` int unsigned NOT NULL AUTO_INCREMENT,
  `vpa` varchar(100) NOT NULL,
  `provider` varchar(50) DEFAULT NULL,
  `reputation_score` decimal(5,2) DEFAULT NULL,
  `total_reports` int unsigned NOT NULL DEFAULT '0',
  `status` varchar(20) NOT NULL DEFAULT 'UNVERIFIED',
  PRIMARY KEY (`upi_id`),
  UNIQUE KEY `uq_upi_vpa` (`vpa`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `report_phone` (
  `report_id` int unsigned NOT NULL,
  `phone_id` int unsigned NOT NULL,
  PRIMARY KEY (`report_id`,`phone_id`),
  KEY `fk_rp_phone` (`phone_id`),
  CONSTRAINT `fk_rp_phone` FOREIGN KEY (`phone_id`) REFERENCES `phone_number` (`phone_id`),
  CONSTRAINT `fk_rp_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `report_email` (
  `report_id` int unsigned NOT NULL,
  `email_id` int unsigned NOT NULL,
  PRIMARY KEY (`report_id`,`email_id`),
  KEY `fk_re_email` (`email_id`),
  CONSTRAINT `fk_re_email` FOREIGN KEY (`email_id`) REFERENCES `email_address` (`email_id`),
  CONSTRAINT `fk_re_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `report_url` (
  `report_id` int unsigned NOT NULL,
  `url_id` int unsigned NOT NULL,
  PRIMARY KEY (`report_id`,`url_id`),
  KEY `fk_ru_url` (`url_id`),
  CONSTRAINT `fk_ru_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`),
  CONSTRAINT `fk_ru_url` FOREIGN KEY (`url_id`) REFERENCES `url` (`url_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `report_upi` (
  `report_id` int unsigned NOT NULL,
  `upi_id` int unsigned NOT NULL,
  PRIMARY KEY (`report_id`,`upi_id`),
  KEY `fk_rupi_upi` (`upi_id`),
  CONSTRAINT `fk_rupi_report` FOREIGN KEY (`report_id`) REFERENCES `scam_report` (`report_id`),
  CONSTRAINT `fk_rupi_upi` FOREIGN KEY (`upi_id`) REFERENCES `upi_id` (`upi_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
