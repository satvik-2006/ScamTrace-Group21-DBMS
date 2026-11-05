"""ScamTrace: course project frontend/API with a relational SQL backend."""
from __future__ import annotations
from contextlib import asynccontextmanager
import os, re
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from sqlalchemy import select, func, or_, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / '.env')
except ImportError:
    pass
from .db import make_engine, make_sessionmaker, initialize
from .models import (User, Role, ScamCategory, ScamPattern, ScamReport, ModerationAction,
    AuditLog, Evidence, ReportConfirmation, URL, PhoneNumber, UPI, EmailAddress,
    ReportURL, ReportPhone, ReportUPI, ReportEmail, RiskAnalysis, RiskFactor, AnalysisRiskFactor)
from .security import hash_password, verify_password, make_session, parse_session, csrf_for, check_csrf
from .risk import score_report

ROOT = Path(__file__).resolve().parent
TEMPLATES = Environment(loader=FileSystemLoader(ROOT/'templates'), autoescape=select_autoescape(['html','xml']))
SECRET = os.environ.get('SCAMTRACE_SECRET_KEY','')
if len(SECRET) < 32:
    # Temporary secret is appropriate only for local demo; all sessions expire on restart.
    SECRET = os.urandom(32).hex()
ENGINE = make_engine()
SessionLocal = make_sessionmaker(ENGINE)
@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize(ENGINE)
    if ENGINE.dialect.name == 'sqlite' and os.environ.get('SCAMTRACE_SEED_DEMO','1') == '1':
        from .seed_demo import seed_demo
        seed_demo(ENGINE)
    yield

app = FastAPI(title='ScamTrace', docs_url='/api/docs', redoc_url=None, lifespan=lifespan)
app.mount('/static', StaticFiles(directory=ROOT/'static'), name='static')

@app.middleware('http')
async def sessions(request: Request, call_next):
    token = request.cookies.get('scamtrace_session')
    if parse_session(SECRET, token) is None:
        token = make_session(SECRET, 0)
        fresh = True
    else: fresh = False
    request.state.session_token = token
    response = await call_next(request)
    if fresh:
        response.set_cookie('scamtrace_session',token,httponly=True,samesite='lax',secure=os.environ.get('COOKIE_SECURE')=='1',max_age=86400)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return response

def current_user(request, db):
    uid = parse_session(SECRET, request.state.session_token)
    return db.get(User,uid) if uid else None

def user_role(user, db):
    role = db.get(Role,user.role_id) if user else None
    return role.role_name if role else 'GUEST'

def render(request, template, db, *, http_status=200, **kwargs):
    user = current_user(request,db)
    context=dict(request=request,user=user,role=user_role(user,db),csrf=csrf_for(SECRET,request.state.session_token),
                 message=request.query_params.get('message',''),**kwargs)
    return HTMLResponse(TEMPLATES.get_template(template).render(**context),status_code=http_status)

def redirect(path): return RedirectResponse(path,status_code=303)

async def get_form(request):
    ct=request.headers.get('content-type','')
    if 'application/x-www-form-urlencoded' not in ct: raise HTTPException(415,'Use an HTML form')
    body=await request.body()
    if len(body)>30_000: raise HTTPException(413,'Form too large')
    return {k:v[-1].strip() for k,v in parse_qs(body.decode('utf-8'),keep_blank_values=True).items()}

async def post_form(request):
    values=await get_form(request)
    if not check_csrf(SECRET,request.state.session_token,values.get('csrf_token')):
        raise HTTPException(403,'Invalid CSRF token')
    return values

def only_user(request,db,allowed=None):
    user=current_user(request,db)
    if not user: raise HTTPException(401,'Please sign in')
    if allowed and user_role(user,db) not in allowed: raise HTTPException(403,'Insufficient permissions')
    return user

def log(db,request,user,action,kind,entity_id):
    db.add(AuditLog(user_id=user.user_id,action=action,entity_type=kind,entity_id=entity_id,ip_address=request.client.host if request.client else None))

def report_scope(db,user):
    if user and user_role(user,db) in ('ADMIN','MODERATOR'): return True
    return False

@app.get('/health')
def health(): return {'status':'ok','database':ENGINE.dialect.name,'app':'ScamTrace','document_store':mongo_status()}

@app.get('/',response_class=HTMLResponse)
def home(request:Request):
    with SessionLocal() as db:
        viewer=current_user(request,db); private=report_scope(db,viewer)
        base=select(ScamReport)
        if not private: base=base.where(ScamReport.status=='VERIFIED')
        rows=db.scalars(base.order_by(ScamReport.reported_at.desc()).limit(6)).all()
        total=db.scalar(select(func.count()).select_from(ScamReport).where(*([] if private else [ScamReport.status=='VERIFIED']))) or 0
        pending=db.scalar(select(func.count()).select_from(ScamReport).where(ScamReport.status=='PENDING')) if private else None
        cats=db.execute(select(ScamCategory.category_name,func.count(ScamReport.report_id)).outerjoin(ScamReport, (ScamCategory.category_id==ScamReport.category_id) & (True if private else ScamReport.status=='VERIFIED')).group_by(ScamCategory.category_id).order_by(func.count(ScamReport.report_id).desc())).all()
        return render(request,'home.html',db,reports=rows,total=total,pending=pending,verified=db.scalar(select(func.count()).select_from(ScamReport).where(ScamReport.status=='VERIFIED')) or 0,
                      categories=cats,category_map={c.category_id:c.category_name for c in db.scalars(select(ScamCategory)).all()})

@app.get('/reports',response_class=HTMLResponse)
def reports(request:Request,q:str='',category:int=0,status:str=''):
    with SessionLocal() as db:
        user=current_user(request,db); private=report_scope(db,user)
        query=select(ScamReport,ScamCategory.category_name,User.name).join(ScamCategory).join(User)
        if not private: query=query.where(ScamReport.status=='VERIFIED')
        elif status and status in ('PENDING','VERIFIED','REJECTED'): query=query.where(ScamReport.status==status)
        if category: query=query.where(ScamReport.category_id==category)
        if q: query=query.where(or_(ScamReport.title.ilike('%'+q[:100]+'%'),ScamReport.description.ilike('%'+q[:100]+'%')))
        rows=db.execute(query.order_by(ScamReport.reported_at.desc(),ScamReport.report_id.desc()).limit(100)).all()
        return render(request,'reports.html',db,rows=rows,categories=db.scalars(select(ScamCategory)).all(),q=q,category=category,status=status)

@app.get('/reports/new',response_class=HTMLResponse)
def report_new(request:Request):
    with SessionLocal() as db:
        user=only_user(request,db)
        return render(request,'new_report.html',db,categories=db.scalars(select(ScamCategory)).all(),error='')

@app.post('/reports/new')
async def create_report(request:Request):
    values=await post_form(request)
    with SessionLocal() as db:
        user=only_user(request,db)
        title=values.get('title','')[:200]; description=values.get('description','')[:5000]
        if len(title)<8 or len(description)<15: return render(request,'new_report.html',db,http_status=400,categories=db.scalars(select(ScamCategory)).all(),error='Title must be 8+ characters and description 15+ characters.')
        try: category=db.get(ScamCategory,int(values.get('category_id','0')))
        except ValueError: category=None
        if not category: raise HTTPException(400,'Invalid category')
        source=values.get('source_type','Other')[:50]
        score,level,signals=score_report(title,description,category.category_name)
        report=ScamReport(user_id=user.user_id,category_id=category.category_id,title=title,description=description,source_type=source,risk_score=score,status='PENDING')
        db.add(report);db.flush()
        analysis=RiskAnalysis(report_id=report.report_id,risk_score=score,risk_level=level,model_version='rules-v1')
        db.add(analysis);db.flush()
        for name,weight in signals:
            factor=db.scalar(select(RiskFactor).where(RiskFactor.factor_name==name))
            if not factor:
                factor=RiskFactor(factor_name=name,weight=weight,description='Deterministic rule');db.add(factor);db.flush()
            db.add(AnalysisRiskFactor(analysis_id=analysis.analysis_id,factor_id=factor.factor_id,contribution_score=weight,detected=True))
        typ=values.get('indicator_type',''); raw=values.get('indicator','')[:500].strip()
        if raw: attach_indicator(db,report.report_id,typ,raw)
        note=values.get('evidence_note','')[:1000]
        if note: db.add(Evidence(report_id=report.report_id,evidence_type='TEXT_NOTE',description=note))
        log(db,request,user,'CREATE','scam_report',report.report_id)
        db.commit()
        if note:
            try: store_evidence(report.report_id, 'TEXT_NOTE', note, {'submitted_by': user.user_id})
            except Exception: pass
        return redirect(f'/reports/{report.report_id}?message=Report+submitted+for+moderation')

def attach_indicator(db,report_id,kind,raw):
    if kind=='URL':
        parsed=urlparse(raw)
        if parsed.scheme not in ('http','https') or not parsed.netloc or len(raw)>500: raise HTTPException(400,'Enter a valid HTTP or HTTPS URL')
        item=db.scalar(select(URL).where(URL.url==raw))
        if not item: item=URL(url=raw,domain=parsed.hostname, total_reports=0,status='UNVERIFIED');db.add(item);db.flush()
        db.add(ReportURL(report_id=report_id,url_id=item.url_id));item.total_reports+=1
    elif kind=='PHONE':
        if not re.fullmatch(r'\+?[0-9]{8,15}',raw): raise HTTPException(400,'Invalid phone')
        item=db.scalar(select(PhoneNumber).where(PhoneNumber.phone_number==raw))
        if not item:item=PhoneNumber(phone_number=raw,total_reports=0,status='UNVERIFIED');db.add(item);db.flush()
        db.add(ReportPhone(report_id=report_id,phone_id=item.phone_id));item.total_reports+=1
    elif kind=='UPI':
        if not re.fullmatch(r'[A-Za-z0-9.\-_]{2,}@[A-Za-z0-9._-]{2,}',raw): raise HTTPException(400,'Invalid UPI VPA')
        item=db.scalar(select(UPI).where(UPI.vpa==raw))
        if not item:item=UPI(vpa=raw,provider=raw.split('@')[1],total_reports=0,status='UNVERIFIED');db.add(item);db.flush()
        db.add(ReportUPI(report_id=report_id,upi_id=item.upi_id));item.total_reports+=1
    elif kind=='EMAIL':
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',raw) or len(raw)>150: raise HTTPException(400,'Invalid email')
        item=db.scalar(select(EmailAddress).where(EmailAddress.email_address==raw))
        if not item:item=EmailAddress(email_address=raw,domain=raw.split('@')[1],total_reports=0,status='UNVERIFIED');db.add(item);db.flush()
        db.add(ReportEmail(report_id=report_id,email_id=item.email_id));item.total_reports+=1
    else: raise HTTPException(400,'Unknown indicator type')

@app.get('/reports/{report_id}',response_class=HTMLResponse)
def report_detail(request:Request,report_id:int):
    with SessionLocal() as db:
        report=db.get(ScamReport,report_id)
        if not report: raise HTTPException(404,'Report not found')
        user=current_user(request,db)
        if report.status!='VERIFIED' and not (user and (report_scope(db,user) or user.user_id==report.user_id)):
            raise HTTPException(404,'Report not found')
        author=db.get(User,report.user_id)
        analysis=db.scalar(select(RiskAnalysis).where(RiskAnalysis.report_id==report_id).order_by(RiskAnalysis.analysis_id.desc()))
        signals=db.execute(select(RiskFactor.factor_name,AnalysisRiskFactor.contribution_score).join(AnalysisRiskFactor).where(AnalysisRiskFactor.analysis_id==analysis.analysis_id)).all() if analysis else []
        indicators=[]
        for cls,target,key,field,tag in [(ReportURL,URL,'url_id','url','URL'),(ReportPhone,PhoneNumber,'phone_id','phone_number','Phone'),(ReportUPI,UPI,'upi_id','vpa','UPI'),(ReportEmail,EmailAddress,'email_id','email_address','Email')]:
            for value in db.execute(select(getattr(target,field)).join(cls,getattr(cls,key)==getattr(target,key)).where(cls.report_id==report_id)).scalars(): indicators.append((tag,value))
        count=db.scalar(select(func.count()).select_from(ReportConfirmation).where(ReportConfirmation.report_id==report_id)) or 0
        actions=db.execute(select(ModerationAction,User.name).join(User,ModerationAction.moderator_id==User.user_id).where(ModerationAction.report_id==report_id).order_by(ModerationAction.action_timestamp.desc())).all()
        return render(request,'detail.html',db,report=report,author=author,category=db.get(ScamCategory,report.category_id),signals=signals,analysis=analysis,
            indicators=indicators,confirmations=count,actions=actions,evidence=db.scalars(select(Evidence).where(Evidence.report_id==report_id)).all(),
            can_moderate=bool(user and report_scope(db,user) and report.status=='PENDING'),
            can_delete=bool(user and user.user_id==report.user_id and report.status=='PENDING'))

@app.post('/reports/{report_id}/confirm')
async def confirm_report(request:Request,report_id:int):
    values=await post_form(request)
    with SessionLocal() as db:
        user=only_user(request,db); report=db.get(ScamReport,report_id)
        if not report or report.status!='VERIFIED': raise HTTPException(404,'Only verified reports can be confirmed')
        if user.user_id==report.user_id: raise HTTPException(400,'Cannot confirm your own report')
        if db.scalar(select(ReportConfirmation.confirmation_id).where(ReportConfirmation.report_id==report_id,ReportConfirmation.user_id==user.user_id)):
            return redirect(f'/reports/{report_id}?message=Already+confirmed')
        db.add(ReportConfirmation(report_id=report_id,user_id=user.user_id,confirmation_type='AGREE',comment=values.get('comment','')[:300]))
        log(db,request,user,'CONFIRM','scam_report',report_id)
        db.commit()
        return redirect(f'/reports/{report_id}?message=Confirmation+saved')

@app.post('/reports/{report_id}/moderate')
async def moderate(request:Request,report_id:int):
    values=await post_form(request)
    with SessionLocal() as db:
        user=only_user(request,db,('ADMIN','MODERATOR'))
        decision=values.get('action_type')
        if decision not in ('APPROVE','REJECT'): raise HTTPException(400,'Invalid decision')
        report=db.get(ScamReport,report_id)
        if not report or report.status!='PENDING': raise HTTPException(409,'Report is not pending')
        report.status='VERIFIED' if decision=='APPROVE' else 'REJECTED'
        db.add(ModerationAction(report_id=report_id,moderator_id=user.user_id,action_type=decision,reason=values.get('reason','')[:1000]))
        log(db,request,user,decision,'scam_report',report_id)
        db.commit()
        return redirect(f'/reports/{report_id}?message=Moderation+decision+saved')

@app.post('/reports/{report_id}/delete')
async def delete_report(request:Request,report_id:int):
    await post_form(request)
    with SessionLocal() as db:
        user=only_user(request,db);report=db.get(ScamReport,report_id)
        if not report or report.user_id!=user.user_id or report.status!='PENDING': raise HTTPException(403,'Only your own pending reports can be deleted')
        for junction, entity, eid, id_col in [(ReportURL,URL,'url_id','url_id'),(ReportPhone,PhoneNumber,'phone_id','phone_id'),(ReportUPI,UPI,'upi_id','upi_id'),(ReportEmail,EmailAddress,'email_id','email_id')]:
            for rid in db.scalars(select(getattr(junction,eid)).where(junction.report_id==report_id)).all():
                item=db.get(entity,rid)
                if item: item.total_reports=max(0,(item.total_reports or 0)-1)
            db.execute(delete(junction).where(junction.report_id==report_id))
        aids=db.scalars(select(RiskAnalysis.analysis_id).where(RiskAnalysis.report_id==report_id)).all()
        if aids: db.execute(delete(AnalysisRiskFactor).where(AnalysisRiskFactor.analysis_id.in_(aids)))
        for cls in [RiskAnalysis,Evidence,ReportConfirmation,ModerationAction]: db.execute(delete(cls).where(cls.report_id==report_id))
        db.delete(report)
        log(db,request,user,'DELETE','scam_report',report_id)
        db.commit()
        return redirect('/reports?message=Report+deleted')

@app.get('/moderation',response_class=HTMLResponse)
def moderation(request:Request):
    with SessionLocal() as db:
        only_user(request,db,('ADMIN','MODERATOR'))
        reports=db.execute(select(ScamReport,ScamCategory.category_name,User.name).join(ScamCategory).join(User).where(ScamReport.status=='PENDING').order_by(ScamReport.report_id.desc())).all()
        return render(request,'moderation.html',db,rows=reports)

@app.get('/analytics',response_class=HTMLResponse)
def analytics(request:Request):
    with SessionLocal() as db:
        private=report_scope(db,current_user(request,db))
        clause=[] if private else [ScamReport.status=='VERIFIED']
        status_rows=db.execute(select(ScamReport.status,func.count()).where(*clause).group_by(ScamReport.status)).all()
        cats=db.execute(select(ScamCategory.category_name,func.count(ScamReport.report_id),func.avg(ScamReport.risk_score)).join(ScamReport).where(*clause).group_by(ScamCategory.category_id).order_by(func.count(ScamReport.report_id).desc())).all()
        avg=db.scalar(select(func.avg(ScamReport.risk_score)).where(*clause)) or 0
        return render(request,'analytics.html',db,cats=cats,status_rows=status_rows,average=round(float(avg),1),max_count=max([row[1] for row in cats]or[1]))

@app.get('/indicators',response_class=HTMLResponse)
def indicators(request:Request,q:str=''):
    with SessionLocal() as db:
        matches=[]
        if q and len(q.strip())>=3:
            search='%'+q[:150].strip()+'%'
            # Public counts are derived from verified reports, never from unreviewed allegations.
            specs=[(URL,ReportURL,'url','url_id','URL'),(PhoneNumber,ReportPhone,'phone_number','phone_id','Phone'),(UPI,ReportUPI,'vpa','upi_id','UPI'),(EmailAddress,ReportEmail,'email_address','email_id','Email')]
            for cls,link,attr,idcol,kind in specs:
                results=db.execute(select(getattr(cls,attr),func.count(ScamReport.report_id)).join(link,getattr(cls,idcol)==getattr(link,idcol)).join(ScamReport,ScamReport.report_id==link.report_id).where(getattr(cls,attr).ilike(search),ScamReport.status=='VERIFIED').group_by(getattr(cls,idcol)).limit(20)).all()
                matches.extend((kind,val,count) for val,count in results)
        return render(request,'indicators.html',db,matches=matches,q=q)

@app.get('/login',response_class=HTMLResponse)
def login_page(request:Request):
    with SessionLocal() as db:return render(request,'login.html',db,error='')

@app.post('/login')
async def login(request:Request):
    values=await post_form(request)
    with SessionLocal() as db:
        email=values.get('email','').lower()[:150]
        user=db.scalar(select(User).where(func.lower(User.email)==email))
        if not user or not verify_password(values.get('password',''),user.password_hash):
            return render(request,'login.html',db,http_status=401,error='Invalid email or password')
        if not user.password_hash.startswith('pbkdf2_sha256$'):
            user.password_hash=hash_password(values.get('password',''))
        user.last_login=datetime.now(UTC).replace(tzinfo=None);db.commit()
        response=redirect('/')
        response.set_cookie('scamtrace_session',make_session(SECRET,user.user_id),httponly=True,samesite='lax',secure=os.environ.get('COOKIE_SECURE')=='1',max_age=86400)
        return response

@app.post('/logout')
async def logout(request:Request):
    await post_form(request)
    response=redirect('/login?message=Signed+out')
    response.delete_cookie('scamtrace_session')
    return response

@app.get('/register',response_class=HTMLResponse)
def register_page(request:Request):
    with SessionLocal() as db:return render(request,'register.html',db,error='')

@app.post('/register')
async def register(request:Request):
    values=await post_form(request)
    with SessionLocal() as db:
        name=values.get('name','')[:100]; email=values.get('email','').lower()[:150];password=values.get('password','')
        if len(name)<2 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or len(password)<10:
            return render(request,'register.html',db,http_status=400,error='Enter a name, valid email and password with at least 10 characters.')
        if db.scalar(select(User.user_id).where(User.email==email)):
            return render(request,'register.html',db,http_status=409,error='This email is already registered.')
        role=db.scalar(select(Role).where(Role.role_name=='USER'))
        user=User(name=name,email=email,password_hash=hash_password(password),role_id=role.role_id)
        db.add(user); db.commit()
        return redirect('/login?message=Account+created')

# JSON API consumed by the Next.js frontend. The original server-rendered demo remains available.
from fastapi import Body
from .mongo_store import store_evidence, search_evidence, status as mongo_status

@app.get('/api/v1/session')
def api_session(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        return {'user': ({'name': user.name, 'email': user.email, 'role': user_role(user, db)} if user else None),
                'csrf': csrf_for(SECRET, request.state.session_token)}

@app.post('/api/v1/auth/login')
def api_login(request: Request, payload: dict = Body(...), x_csrf_token: str | None = Header(default=None)):
    if not check_csrf(SECRET, request.state.session_token, x_csrf_token): raise HTTPException(403, 'Invalid CSRF token')
    with SessionLocal() as db:
        email = str(payload.get('email', '')).lower().strip()[:150]
        user = db.scalar(select(User).where(func.lower(User.email) == email))
        password = str(payload.get('password', ''))
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(401, 'Invalid email or password')
        if not user.password_hash.startswith('pbkdf2_sha256$'):
            user.password_hash = hash_password(password)
        user.last_login = datetime.now(UTC).replace(tzinfo=None)
        db.commit()
        response = JSONResponse({'ok': True})
        response.set_cookie('scamtrace_session', make_session(SECRET, user.user_id), httponly=True,
                            samesite='lax', secure=os.environ.get('COOKIE_SECURE') == '1', max_age=86400)
        return response

@app.post('/api/v1/auth/register')
def api_register(request: Request, payload: dict = Body(...), x_csrf_token: str | None = Header(default=None)):
    if not check_csrf(SECRET, request.state.session_token, x_csrf_token): raise HTTPException(403, 'Invalid CSRF token')
    with SessionLocal() as db:
        name = str(payload.get('name', '')).strip()[:100]
        email = str(payload.get('email', '')).lower().strip()[:150]
        password = str(payload.get('password', ''))
        if len(name) < 2 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or len(password) < 10:
            raise HTTPException(400, 'Enter a name, valid email and password with at least 10 characters.')
        if db.scalar(select(User.user_id).where(User.email == email)):
            raise HTTPException(409, 'This email is already registered.')
        role = db.scalar(select(Role).where(Role.role_name == 'USER'))
        if not role:
            raise HTTPException(500, 'USER role is missing; initialize the database first.')
        db.add(User(name=name, email=email, password_hash=hash_password(password), role_id=role.role_id))
        try: db.commit()
        except IntegrityError:
            db.rollback(); raise HTTPException(409, 'This email is already registered.')
        return {'ok': True}

@app.post('/api/v1/auth/logout')
def api_logout(request: Request, x_csrf_token: str | None = Header(default=None)):
    if not check_csrf(SECRET, request.state.session_token, x_csrf_token):
        raise HTTPException(403, 'Invalid CSRF token')
    response = JSONResponse({'ok': True}); response.set_cookie('scamtrace_session', make_session(SECRET, 0), httponly=True, samesite='lax', secure=os.environ.get('COOKIE_SECURE') == '1', max_age=86400); return response

@app.get('/api/v1/categories')
def api_categories():
    with SessionLocal() as db:
        return {'items': [{'category_id': c.category_id, 'category_name': c.category_name}
                          for c in db.scalars(select(ScamCategory).order_by(ScamCategory.category_name)).all()]}

@app.get('/api/v1/reports')
def api_reports(request: Request, status: str = ''):
    with SessionLocal() as db:
        user = current_user(request, db); private = report_scope(db, user)
        query = select(ScamReport, ScamCategory.category_name).join(ScamCategory)
        if not private: query = query.where(ScamReport.status == 'VERIFIED')
        elif status in ('PENDING', 'VERIFIED', 'REJECTED'): query = query.where(ScamReport.status == status)
        rows = db.execute(query.order_by(ScamReport.reported_at.desc()).limit(100)).all()
        return {'items': [{'report_id': r.report_id, 'title': r.title, 'description': r.description,
            'category': category, 'status': r.status, 'risk_score': float(r.risk_score or 0),
            'reported_at': r.reported_at.isoformat() if r.reported_at else None} for r, category in rows]}

@app.get('/api/v1/analytics')
def api_analytics(request: Request):
    with SessionLocal() as db:
        private = report_scope(db, current_user(request, db)); clause = [] if private else [ScamReport.status == 'VERIFIED']
        total = db.scalar(select(func.count()).select_from(ScamReport).where(*clause)) or 0
        verified = db.scalar(select(func.count()).select_from(ScamReport).where(ScamReport.status == 'VERIFIED')) or 0
        pending = db.scalar(select(func.count()).select_from(ScamReport).where(ScamReport.status == 'PENDING')) or 0
        avg = db.scalar(select(func.avg(ScamReport.risk_score)).where(*clause)) or 0
        return {'total_reports': total, 'verified_reports': verified, 'pending_reports': pending,
                'average_risk': round(float(avg), 1), 'mongo': mongo_status()}

@app.get('/api/v1/indicators')
def api_indicators(q: str = ''):
    with SessionLocal() as db:
        matches = []
        if len(q.strip()) >= 3:
            search = '%' + q[:150].strip() + '%'
            specs = [(URL, ReportURL, 'url', 'url_id', 'URL'), (PhoneNumber, ReportPhone, 'phone_number', 'phone_id', 'Phone'),
                     (UPI, ReportUPI, 'vpa', 'upi_id', 'UPI'), (EmailAddress, ReportEmail, 'email_address', 'email_id', 'Email')]
            for cls, link, attr, idcol, kind in specs:
                rows = db.execute(select(getattr(cls, attr), func.count(ScamReport.report_id)).join(link, getattr(cls, idcol) == getattr(link, idcol)).join(ScamReport, ScamReport.report_id == link.report_id).where(getattr(cls, attr).ilike(search), ScamReport.status == 'VERIFIED').group_by(getattr(cls, idcol)).limit(20)).all()
                matches.extend({'kind': kind, 'value': value, 'verified_reports': count} for value, count in rows)
        return {'items': matches}

@app.get('/api/v1/evidence-search')
def api_evidence_search(request: Request, q: str = ''):
    # Evidence follows the same publication boundary as reports: public users see
    # verified evidence only; report owners and moderators can see their own/private scope.
    documents = search_evidence(q)
    with SessionLocal() as db:
        user = current_user(request, db)
        allowed = report_scope(db, user)
        ids = [d['report_id'] for d in documents]
        if not allowed and ids:
            visibility = [ScamReport.report_id.in_(ids), ScamReport.status == 'VERIFIED']
            if user:
                visibility = [ScamReport.report_id.in_(ids), or_(ScamReport.status == 'VERIFIED', ScamReport.user_id == user.user_id)]
            visible = set(db.scalars(select(ScamReport.report_id).where(*visibility)).all())
            documents = [d for d in documents if d['report_id'] in visible]
    return {'items': documents, 'mongo': mongo_status()}

@app.post('/api/v1/reports')
def api_create_report(request: Request, payload: dict = Body(...), x_csrf_token: str | None = Header(default=None)):
    if not check_csrf(SECRET, request.state.session_token, x_csrf_token): raise HTTPException(403, 'Invalid CSRF token')
    with SessionLocal() as db:
        user = only_user(request, db)
        title = str(payload.get('title', '')).strip()[:200]; description = str(payload.get('description', '')).strip()[:5000]
        if len(title) < 8 or len(description) < 15: raise HTTPException(400, 'Title must be 8+ characters and description 15+ characters.')
        try: category = db.get(ScamCategory, int(payload.get('category_id', 0)))
        except (ValueError, TypeError): category = None
        if not category: raise HTTPException(400, 'Invalid category')
        source = str(payload.get('source_type', 'Other'))[:50]
        score, level, signals = score_report(title, description, category.category_name)
        try:
            report = ScamReport(user_id=user.user_id, category_id=category.category_id, title=title, description=description,
                                source_type=source, risk_score=score, status='PENDING')
            db.add(report); db.flush()
            analysis = RiskAnalysis(report_id=report.report_id, risk_score=score, risk_level=level, model_version='rules-v1')
            db.add(analysis); db.flush()
            for name, weight in signals:
                factor = db.scalar(select(RiskFactor).where(RiskFactor.factor_name == name))
                if not factor:
                    factor = RiskFactor(factor_name=name, weight=weight, description='Deterministic rule'); db.add(factor); db.flush()
                db.add(AnalysisRiskFactor(analysis_id=analysis.analysis_id, factor_id=factor.factor_id, contribution_score=weight, detected=True))
            raw = str(payload.get('indicator', '')).strip()[:500]
            if raw: attach_indicator(db, report.report_id, str(payload.get('indicator_type', '')), raw)
            evidence_note = str(payload.get('evidence_note', '')).strip()[:4000]
            if evidence_note: db.add(Evidence(report_id=report.report_id, evidence_type='TEXT_NOTE', description=evidence_note))
            log(db, request, user, 'CREATE', 'scam_report', report.report_id)
            db.commit()
            # MongoDB is the document/evidence store; SQL keeps the evidence reference and remains authoritative.
            if evidence_note:
                try: store_evidence(report.report_id, 'TEXT_NOTE', evidence_note, {'submitted_by': user.user_id})
                except Exception: pass  # report remains valid; health endpoint exposes MongoDB availability
            return {'ok': True, 'report_id': report.report_id, 'risk_score': score, 'risk_level': level, 'signals': [n for n, _ in signals]}
        except Exception:
            db.rollback(); raise

@app.post('/api/v1/reports/{report_id}/moderate')
def api_moderate(request: Request, report_id: int, payload: dict = Body(...), x_csrf_token: str | None = Header(default=None)):
    if not check_csrf(SECRET, request.state.session_token, x_csrf_token): raise HTTPException(403, 'Invalid CSRF token')
    with SessionLocal() as db:
        user = only_user(request, db, ('ADMIN', 'MODERATOR'))
        decision = payload.get('action_type')
        if decision not in ('APPROVE', 'REJECT'): raise HTTPException(400, 'Invalid decision')
        report = db.get(ScamReport, report_id)
        if not report or report.status != 'PENDING': raise HTTPException(409, 'Report is not pending')
        report.status = 'VERIFIED' if decision == 'APPROVE' else 'REJECTED'
        db.add(ModerationAction(report_id=report_id, moderator_id=user.user_id, action_type=decision, reason=str(payload.get('reason', ''))[:1000]))
        log(db, request, user, decision, 'scam_report', report_id); db.commit()
        return {'ok': True, 'status': report.status}
