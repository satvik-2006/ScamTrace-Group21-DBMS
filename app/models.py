"""SQLAlchemy mappings for the 20 ScamTrace tables in the Chen ER diagram."""
from datetime import datetime
from sqlalchemy import String, Integer, Text, Date, DateTime, Numeric, ForeignKey, Boolean, CheckConstraint, UniqueConstraint, Index, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

def idcol():
    return mapped_column(Integer, primary_key=True, autoincrement=True)

def nowcol():
    return mapped_column(DateTime, server_default=func.current_timestamp(), nullable=False)

class Role(Base):
    __tablename__ = 'role'
    __table_args__ = (UniqueConstraint('role_name', name='uq_role_name'),)
    role_id: Mapped[int] = idcol()
    role_name: Mapped[str] = mapped_column(String(50), nullable=False)

class User(Base):
    __tablename__ = 'user'
    __table_args__ = (UniqueConstraint('email', name='uq_user_email'),)
    user_id: Mapped[int] = idcol()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(150), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(25))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey('role.role_id'), nullable=False)
    created_at: Mapped[datetime] = nowcol()
    last_login: Mapped[datetime | None] = mapped_column(DateTime)

class ScamCategory(Base):
    __tablename__ = 'scam_category'
    __table_args__ = (UniqueConstraint('category_name', name='uq_category_name'),)
    category_id: Mapped[int] = idcol()
    category_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

class ScamPattern(Base):
    __tablename__ = 'scam_pattern'
    __table_args__ = (CheckConstraint('report_count >= 0', name='chk_report_count'),)
    pattern_id: Mapped[int] = idcol()
    category_id: Mapped[int] = mapped_column(ForeignKey('scam_category.category_id'), nullable=False)
    pattern_name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    risk_level: Mapped[str | None] = mapped_column(String(20))
    first_detected: Mapped[datetime | None] = mapped_column(Date)
    report_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='ACTIVE', nullable=False)

class ScamReport(Base):
    __tablename__ = 'scam_report'
    __table_args__ = (CheckConstraint('risk_score BETWEEN 0 AND 100', name='chk_risk_score'), Index('idx_report_status', 'status'),)
    report_id: Mapped[int] = idcol()
    user_id: Mapped[int] = mapped_column(ForeignKey('user.user_id'), nullable=False)
    category_id: Mapped[int] = mapped_column(ForeignKey('scam_category.category_id'), nullable=False)
    pattern_id: Mapped[int | None] = mapped_column(ForeignKey('scam_pattern.pattern_id'))
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[str | None] = mapped_column(String(50))
    reported_at: Mapped[datetime] = nowcol()
    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    status: Mapped[str] = mapped_column(String(20), default='PENDING', nullable=False)

class RiskAnalysis(Base):
    __tablename__ = 'risk_analysis'
    analysis_id: Mapped[int] = idcol()
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    risk_level: Mapped[str | None] = mapped_column(String(20))
    model_version: Mapped[str | None] = mapped_column(String(30))
    analyzed_at: Mapped[datetime] = nowcol()

class RiskFactor(Base):
    __tablename__ = 'risk_factor'
    factor_id: Mapped[int] = idcol()
    factor_name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    weight: Mapped[float | None] = mapped_column(Numeric(5, 2))

class AnalysisRiskFactor(Base):
    __tablename__ = 'analysis_risk_factor'
    analysis_id: Mapped[int] = mapped_column(ForeignKey('risk_analysis.analysis_id'), primary_key=True)
    factor_id: Mapped[int] = mapped_column(ForeignKey('risk_factor.factor_id'), primary_key=True)
    contribution_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    detected: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

class ModerationAction(Base):
    __tablename__ = 'moderation_action'
    action_id: Mapped[int] = idcol()
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), nullable=False)
    moderator_id: Mapped[int] = mapped_column(ForeignKey('user.user_id'), nullable=False)
    action_type: Mapped[str | None] = mapped_column(String(50))
    reason: Mapped[str | None] = mapped_column(Text)
    action_timestamp: Mapped[datetime] = nowcol()

class AuditLog(Base):
    __tablename__ = 'audit_log'
    audit_id: Mapped[int] = idcol()
    user_id: Mapped[int] = mapped_column(ForeignKey('user.user_id'), nullable=False)
    action: Mapped[str | None] = mapped_column(String(100))
    entity_type: Mapped[str | None] = mapped_column(String(50))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[datetime] = nowcol()
    ip_address: Mapped[str | None] = mapped_column(String(45))

class Evidence(Base):
    __tablename__ = 'evidence'
    evidence_id: Mapped[int] = idcol()
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), nullable=False)
    evidence_type: Mapped[str | None] = mapped_column(String(50))
    file_path: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    uploaded_at: Mapped[datetime] = nowcol()

class ReportConfirmation(Base):
    __tablename__ = 'report_confirmation'
    __table_args__ = (UniqueConstraint('report_id','user_id',name='uq_confirmation_report_user'),)
    confirmation_id: Mapped[int] = idcol()
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.user_id'), nullable=False)
    confirmation_type: Mapped[str | None] = mapped_column(String(30))
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = nowcol()

class URL(Base):
    __tablename__ = 'url'
    __table_args__ = (Index('uq_url', 'url', unique=True, mysql_length=255),)
    url_id: Mapped[int] = idcol()
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(150))
    reputation_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    total_reports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='UNVERIFIED', nullable=False)

class PhoneNumber(Base):
    __tablename__ = 'phone_number'
    __table_args__ = (UniqueConstraint('phone_number', name='uq_phone_number'),)
    phone_id: Mapped[int] = idcol()
    phone_number: Mapped[str] = mapped_column(String(20), nullable=False)
    reputation_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    total_reports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='UNVERIFIED', nullable=False)

class UPI(Base):
    __tablename__ = 'upi_id'
    __table_args__ = (UniqueConstraint('vpa', name='uq_upi_vpa'),)
    upi_id: Mapped[int] = idcol()
    vpa: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(50))
    reputation_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    total_reports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='UNVERIFIED', nullable=False)

class EmailAddress(Base):
    __tablename__ = 'email_address'
    __table_args__ = (UniqueConstraint('email_address', name='uq_email_address'),)
    email_id: Mapped[int] = idcol()
    email_address: Mapped[str] = mapped_column(String(150), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(100))
    reputation_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    total_reports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='UNVERIFIED', nullable=False)

class ReportURL(Base):
    __tablename__ = 'report_url'
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey('url.url_id'), primary_key=True)
class ReportPhone(Base):
    __tablename__ = 'report_phone'
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), primary_key=True)
    phone_id: Mapped[int] = mapped_column(ForeignKey('phone_number.phone_id'), primary_key=True)
class ReportUPI(Base):
    __tablename__ = 'report_upi'
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), primary_key=True)
    upi_id: Mapped[int] = mapped_column(ForeignKey('upi_id.upi_id'), primary_key=True)
class ReportEmail(Base):
    __tablename__ = 'report_email'
    report_id: Mapped[int] = mapped_column(ForeignKey('scam_report.report_id'), primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey('email_address.email_id'), primary_key=True)
