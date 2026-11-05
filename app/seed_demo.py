"""Synthetic local demo; never run this against an imported real database."""
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Role, User, ScamCategory, ScamPattern, ScamReport, URL, ReportURL, ModerationAction, RiskFactor, RiskAnalysis
from .security import hash_password

CATEGORIES = [
 ('Phishing','Fake messages and websites seeking credentials'),
 ('UPI Fraud','Fraudulent UPI collect and refund requests'),
 ('Job Scam','Fake jobs requesting upfront payment'),
 ('Lottery Scam','Fraudulent prizes and lottery fees'),
 ('Investment Scam','Unrealistic investment return promises'),
 ('Impersonation Call','Calls impersonating trusted organizations'),
]
PATTERNS = [(1,'Fake Bank KYC Update SMS','HIGH'),(2,'Collect Request Refund Trick','CRITICAL'),(3,'Work From Home Task Payment','MEDIUM'),(4,'Lottery Winner Message','MEDIUM'),(5,'Crypto Doubling Telegram Group','HIGH'),(6,'Fake Courier Customs Call','HIGH'),(1,'Electricity Bill Disconnection','MEDIUM')]
REPORTS = [
 (3,1,1,'Fake SBI KYC SMS with link','SMS with a fake bank verification link','SMS',82.50,'VERIFIED'),
 (4,1,1,'HDFC KYC expiry message','Message said account freezes in 24 hours','SMS',78,'VERIFIED'),
 (3,2,2,'Refund collect request on PhonePe','Caller sent a collect request as a refund','UPI_APP',91,'VERIFIED'),
 (5,2,2,'GPay refund scam from marketplace buyer','Buyer asked me to approve a request','Marketplace',88.75,'PENDING'),
 (4,3,3,'WhatsApp task job paying per like','Paid first tasks then asked for deposit','WhatsApp',64,'PENDING'),
 (5,4,4,'Lottery winner 25 lakh message','SMS requesting a processing fee','SMS',55.50,'REJECTED'),
 (3,5,5,'Telegram crypto doubling group','Group showed fake withdrawal screenshots','Telegram',85,'VERIFIED'),
 (4,6,6,'Parcel customs impersonation call','Automated call demanding parcel fees','Phone Call',79.25,'PENDING'),
 (5,1,None,'Unknown phishing email about lock','Email said account was locked','Email',48,'PENDING'),
 (3,2,2,'Fake refund collect request again','Same refund trick through a different app','UPI_APP',90,'PENDING'),
 (4,1,7,'Electricity bill disconnection SMS','Fake payment link asks for Rs 10','SMS',66,'PENDING'),
]

def seed_demo(engine):
    with Session(engine) as session:
        if session.scalar(select(Role.role_id).limit(1)) is not None: return False
        session.add_all([Role(role_id=i, role_name=name) for i, name in enumerate(['ADMIN','MODERATOR','USER'],1)])
        session.flush()
        for i,(name,email,role) in enumerate([
            ('Demo Admin','admin@demo.test',1),('Demo Moderator','moderator@demo.test',2),
            ('Rohan Das','rohan@demo.test',3),('Priya Nair','priya@demo.test',3),
            ('Kiran Rao','kiran@demo.test',3)],1):
            session.add(User(user_id=i,name=name,email=email,phone=None,password_hash=hash_password('DemoPass123!'),role_id=role))
        for i,(name,desc) in enumerate(CATEGORIES,1): session.add(ScamCategory(category_id=i,category_name=name,description=desc))
        session.flush()
        for i,(category,name,level) in enumerate(PATTERNS,1):
            session.add(ScamPattern(pattern_id=i,category_id=category,pattern_name=name,risk_level=level,report_count=0,status='ACTIVE'))
        session.flush()
        for i,(owner,category,pattern,title,desc,source,score,status) in enumerate(REPORTS,1):
            session.add(ScamReport(report_id=i,user_id=owner,category_id=category,pattern_id=pattern,title=title,description=desc,source_type=source,risk_score=score,status=status))
        session.flush()
        session.add(ModerationAction(report_id=3,moderator_id=2,action_type='APPROVE',reason='Example reviewed case'))
        session.add(URL(url_id=1,url='http://electricity-bill-demo.invalid/pay',domain='electricity-bill-demo.invalid',total_reports=1,status='UNVERIFIED'))
        session.flush()
        session.add(ReportURL(report_id=11,url_id=1))
        for name,weight in [('Urgent pressure',16),('Payment or deposit request',24),('Impersonation claim',18),('External link',12),('High-return promise',20)]:
            session.add(RiskFactor(factor_name=name,weight=weight,description='Rules-based demonstration signal'))
        for i,report in enumerate(REPORTS,1):
            score = report[6]
            session.add(RiskAnalysis(report_id=i,risk_score=score,risk_level='CRITICAL' if score >= 85 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 35 else 'LOW',model_version='imported-demo'))
        session.commit()
        return True
