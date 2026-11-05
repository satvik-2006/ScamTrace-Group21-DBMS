-- Safe, synthetic reference rows for a fresh ScamTrace database.
-- Contains no users, password hashes, reports, or real indicator values.
-- INSERT IGNORE makes this script safe to rerun against the same seed IDs.
USE scamtrace;

INSERT IGNORE INTO role (role_id,role_name) VALUES
    (1,'ADMIN'),
    (2,'MODERATOR'),
    (3,'USER');

INSERT IGNORE INTO scam_category (category_id,category_name,description) VALUES
    (1,'Phishing','Fake messages or sites that seek credentials'),
    (2,'UPI Fraud','Fraudulent collect requests and refund claims'),
    (3,'Job Scam','Fake jobs requesting upfront payments'),
    (4,'Lottery Scam','Prize messages requesting processing fees'),
    (5,'Investment Scam','Unrealistic investment return promises'),
    (6,'Impersonation Call','Calls impersonating trusted organizations');

INSERT IGNORE INTO scam_pattern
    (pattern_id,category_id,pattern_name,risk_level,report_count,status) VALUES
    (1,1,'Fake Bank KYC Update Message','HIGH',0,'ACTIVE'),
    (2,2,'Collect Request Refund Trick','CRITICAL',0,'ACTIVE'),
    (3,3,'Work From Home Task Payment','MEDIUM',0,'ACTIVE'),
    (4,4,'Lottery Winner Fee Request','MEDIUM',0,'ACTIVE'),
    (5,5,'Crypto Doubling Promise','HIGH',0,'ACTIVE'),
    (6,6,'Fake Courier Customs Call','HIGH',0,'ACTIVE'),
    (7,1,'Utility Bill Disconnection Message','MEDIUM',0,'ACTIVE');

INSERT IGNORE INTO risk_factor (factor_id,factor_name,description,weight) VALUES
    (1,'Urgent pressure','Synthetic demo factor',16.00),
    (2,'Payment request','Synthetic demo factor',24.00),
    (3,'Impersonation claim','Synthetic demo factor',18.00),
    (4,'External link','Synthetic demo factor',12.00),
    (5,'Unrealistic return','Synthetic demo factor',20.00);
