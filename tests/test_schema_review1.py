"""Static consistency checks for the submitted ERD and the 20-table SQL schema.
These checks do not execute DDL on a MySQL server.
"""
import re
from pathlib import Path
from sqlalchemy import CheckConstraint, UniqueConstraint
from app.models import Base

SQL = (Path(__file__).resolve().parents[1]/'sql'/'01_core_schema.sql').read_text()
EXPECTED_TABLES = {
    'analysis_risk_factor', 'audit_log', 'email_address', 'evidence',
    'moderation_action', 'phone_number', 'report_confirmation', 'report_email',
    'report_phone', 'report_upi', 'report_url', 'risk_analysis', 'risk_factor',
    'role', 'scam_category', 'scam_pattern', 'scam_report', 'upi_id', 'url', 'user',
}

def test_core_schema_is_exactly_the_20_erd_tables_with_22_foreign_keys():
    tables=re.findall(r'^CREATE TABLE `([^`]+)`',SQL,flags=re.M)
    fks=re.findall(r'\bCONSTRAINT `[^`]+` FOREIGN KEY',SQL)
    assert set(tables)==EXPECTED_TABLES
    assert len(tables)==20
    assert len(fks)==22
    assert 'ddl_test' not in SQL
    assert not re.search(r'^\s*DROP\s+TABLE',SQL,re.M|re.I)

def test_sqlalchemy_mapping_matches_the_core_table_and_foreign_key_counts():
    assert set(Base.metadata.tables)==EXPECTED_TABLES
    assert sum(len(table.foreign_keys) for table in Base.metadata.tables.values())==22

def test_constraint_names_are_unique_and_match_the_sql_checks():
    sql_checks=set(re.findall(r'CONSTRAINT `([^`]+)` CHECK',SQL))
    orm_checks={constraint.name for table in Base.metadata.tables.values()
                for constraint in table.constraints if isinstance(constraint,CheckConstraint)}
    assert sql_checks=={'chk_report_count','chk_risk_score'}
    assert orm_checks==sql_checks

def test_unique_keys_match_the_dump():
    sql_unique_names=set(re.findall(r'UNIQUE KEY `([^`]+)`',SQL))
    orm_unique_names={constraint.name for table in Base.metadata.tables.values()
                      for constraint in table.constraints if isinstance(constraint,UniqueConstraint)}
    orm_unique_names|={index.name for table in Base.metadata.tables.values()
                       for index in table.indexes if index.unique}
    assert sql_unique_names==orm_unique_names

def test_user_schema_retains_the_later_last_login_column():
    block=SQL.split('CREATE TABLE `user` (',1)[1].split(') ENGINE=',1)[0]
    assert '`last_login` timestamp' in block
