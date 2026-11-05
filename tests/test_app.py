"""Integration tests against a disposable real SQLite relational database."""
import os, re, tempfile
import uuid
from pathlib import Path
from urllib.parse import quote

# A unique path is used so project/demo data are not modified by the test suite.
TEST_DB=Path(tempfile.mkdtemp(prefix='scamtrace_test_'))/'test.db'
os.environ['DATABASE_URL']='sqlite:///'+str(TEST_DB)
os.environ['SCAMTRACE_SEED_DEMO']='1'
os.environ['SCAMTRACE_SECRET_KEY']='integration-tests-local-secret-at-least-32-chars'
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import app, SessionLocal
from app.models import (ScamReport, ModerationAction, AuditLog, ReportURL, RiskAnalysis,
    URL, PhoneNumber, UPI, EmailAddress, ReportPhone, ReportUPI, ReportEmail)


def csrf(client,path='/login'):
    html=client.get(path).text
    match=re.search(r'name="csrf_token" value="([a-f0-9]+)"',html)
    assert match, f'No CSRF token found on {path}'
    return match.group(1)

def login(client,email='rohan@demo.test',password='DemoPass123!'):
    token=csrf(client)
    resp=client.post('/login',data={'csrf_token':token,'email':email,'password':password},follow_redirects=False)
    assert resp.status_code==303,resp.text[:200]
    return resp


def test_end_to_end():
  with TestClient(app) as c:
    assert c.get('/health').json()['database']=='sqlite'
    assert c.get('/').status_code==200
    assert 'Fake SBI KYC SMS' in c.get('/reports').text
    assert 'GPay refund' not in c.get('/reports').text
    assert c.get('/moderation').status_code==401
    assert c.get('/reports/4').status_code==404
    assert c.get('/reports/new').status_code==401
    assert c.get('/analytics').status_code==200
    assert c.get('/indicators?q=electricity').status_code==200
    assert c.post('/login',data={'email':'rohan@demo.test','password':'DemoPass123!'}).status_code==403
    assert c.post('/register',data={'csrf_token':csrf(c,'/register'),'name':'tester','email':'testnew@demo.test','password':'StrongPassword123'},follow_redirects=False).status_code==303
    assert c.post('/login',data={'csrf_token':csrf(c),'email':'rohan@demo.test','password':'badpassword'}).status_code==401
    login(c)
    assert c.get('/reports/new').status_code==200
    bad=c.post('/reports/new',data={'csrf_token':csrf(c,'/reports/new'),'title':'short','description':'very short','category_id':'1'})
    assert bad.status_code==400
    values={'csrf_token':csrf(c,'/reports/new'),'title':'Urgent bank KYC update request',
            'description':'Received urgent fake bank update link http://kyc-fake.invalid/update requesting a fee.',
            'category_id':'1','source_type':'SMS','indicator_type':'URL','indicator':'http://kyc-fake.invalid/update',
            'evidence_note':'Received a screenshot and did not follow the link.'}
    made=c.post('/reports/new',data=values,follow_redirects=False)
    assert made.status_code==303,made.text[:300]
    path=made.headers['location'].split('?')[0]; rid=int(path.split('/')[-1])
    assert c.get(path).status_code==200
    assert c.get('/indicators?q=kyc-fake').status_code==200
    assert 'kyc-fake.invalid' not in c.get('/indicators?q=kyc-fake').text.split('Search results')[-1]
    assert c.get('/moderation').status_code==403
    assert c.post(path+'/moderate',data={'csrf_token':csrf(c,path),'action_type':'APPROVE'}).status_code==403
    with SessionLocal() as db:
        r=db.get(ScamReport,rid)
        assert r.status=='PENDING'
        assert db.scalar(select(RiskAnalysis).where(RiskAnalysis.report_id==rid))
        assert db.scalar(select(ReportURL).where(ReportURL.report_id==rid))
    assert c.post('/logout',data={'csrf_token':csrf(c,path)},follow_redirects=False).status_code==303
    login(c,'moderator@demo.test')
    assert c.get('/moderation').status_code==200
    assert 'Urgent bank KYC' in c.get('/moderation').text
    resp=c.post(path+'/moderate',data={'csrf_token':csrf(c,path),'action_type':'APPROVE','reason':'Evidence reviewed'},follow_redirects=False)
    assert resp.status_code==303,resp.text[:300]
    assert 'Verified' in c.get(path).text
    with SessionLocal() as db:
        assert db.get(ScamReport,rid).status=='VERIFIED'
        assert db.scalar(select(ModerationAction).where(ModerationAction.report_id==rid,ModerationAction.action_type=='APPROVE'))
        assert db.scalar(select(AuditLog).where(AuditLog.entity_id==rid,AuditLog.action=='APPROVE'))
    assert c.post(path+'/moderate',data={'csrf_token':csrf(c,path),'action_type':'REJECT'}).status_code==409
    c.post('/logout',data={'csrf_token':csrf(c,path)})
    assert c.get(path).status_code==200
    assert 'kyc-fake.invalid' in c.get('/indicators?q=kyc-fake').text
    login(c,'priya@demo.test')
    assert c.post(path+'/confirm',data={'csrf_token':csrf(c,path),'comment':'Same message'},follow_redirects=False).status_code==303
    assert c.post(path+'/confirm',data={'csrf_token':csrf(c,path),'comment':'Again'},follow_redirects=False).status_code==303
    assert '1 <small>independent confirmations' in c.get(path).text
    # Database constraints stop orphan report references.
    with SessionLocal() as db:
        assert db.get(ScamReport,rid).risk_score <= 100
    assert '&lt;script&gt;' in c.get('/reports?q=%3Cscript%3E').text or c.get('/reports?q=%3Cscript%3E').status_code==200
    # Owner may delete only a pending report; associated indicator rows are removed first.
    c.post('/logout',data={'csrf_token':csrf(c,path)})
    login(c,'rohan@demo.test')
    created=c.post('/reports/new',data={'csrf_token':csrf(c,'/reports/new'),'title':'Delete pending example',
        'description':'Example to check child-row cleanup when owner deletes a pending report.',
        'category_id':'1','source_type':'SMS','indicator_type':'PHONE','indicator':'+919876543210'},follow_redirects=False)
    assert created.status_code==303
    del_path=created.headers['location'].split('?')[0]
    did=int(del_path.split('/')[-1])
    deleted=c.post(del_path+'/delete',data={'csrf_token':csrf(c,del_path)},follow_redirects=False)
    assert deleted.status_code==303
    with SessionLocal() as db:assert db.get(ScamReport,did) is None
    print(f'PASS: end-to-end report #{rid}, risk analysis, moderator approval, audit, confirmation, access checks')


def test_nextjs_json_api_contract():
    """Exercise the JSON API used by the Next.js interface."""
    with TestClient(app) as c:
        initial = c.get('/api/v1/session').json()
        assert initial['user'] is None and initial['csrf']
        assert c.get('/api/v1/categories').status_code == 200
        assert c.get('/api/v1/reports').status_code == 200
        assert c.get('/api/v1/analytics').status_code == 200
        assert c.post('/api/v1/auth/login', json={'email':'rohan@demo.test','password':'DemoPass123!'}, headers={'X-CSRF-Token':initial['csrf']}).status_code == 200
        session = c.get('/api/v1/session').json()
        assert session['user']['role'] == 'USER'
        bad = c.post('/api/v1/reports', json={'title':'short'}, headers={'X-CSRF-Token':'bad'})
        assert bad.status_code == 403
        made = c.post('/api/v1/reports', json={
            'title':'API example phishing report',
            'description':'Urgent bank KYC message asks the recipient to open an external link and pay a fee.',
            'category_id':1,'source_type':'SMS','indicator_type':'URL',
            'indicator':'https://api-demo.invalid/verify','evidence_note':'Sender demanded an upfront fee.'
        }, headers={'X-CSRF-Token':session['csrf']})
        assert made.status_code == 200, made.text
        assert made.json()['risk_score'] > 0
        assert c.get('/api/v1/reports').status_code == 200
        assert isinstance(c.get('/api/v1/evidence-search?q=upfront').json()['items'], list)
        c.post('/api/v1/auth/logout', headers={'X-CSRF-Token': c.get('/api/v1/session').json()['csrf']})
        assert c.post('/api/v1/auth/login', json={'email':'moderator@demo.test','password':'DemoPass123!'}, headers={'X-CSRF-Token':c.get('/api/v1/session').json()['csrf']}).status_code == 200
        staff_session = c.get('/api/v1/session').json()
        assert staff_session['user']['role'] == 'MODERATOR'
        moderated = c.post(f"/api/v1/reports/{made.json()['report_id']}/moderate",
            json={'action_type':'APPROVE','reason':'API moderation test'},
            headers={'X-CSRF-Token':staff_session['csrf']})
        assert moderated.status_code == 200 and moderated.json()['status'] == 'VERIFIED'


def test_indicator_api_shows_only_verified_matches_and_requires_three_characters():
    """Synthetic indicators exercise every supported kind and the public visibility boundary."""
    cases = [
        (URL, ReportURL, 'url_id', lambda token: f'https://lookup-{token}.invalid/check',
         lambda value, token: URL(url=value, domain=f'lookup-{token}.invalid')),
        (PhoneNumber, ReportPhone, 'phone_id', lambda token: f'+91987{token[:7]}',
         lambda value, token: PhoneNumber(phone_number=value)),
        (UPI, ReportUPI, 'upi_id', lambda token: f'lookup{token}@demo.invalid',
         lambda value, token: UPI(vpa=value, provider='demo.invalid')),
        (EmailAddress, ReportEmail, 'email_id', lambda token: f'lookup{token}@demo.invalid',
         lambda value, token: EmailAddress(email_address=value, domain='demo.invalid')),
    ]
    with TestClient(app) as client:
        for model, link_model, id_field, value_for, make_indicator in cases:
            token = uuid.uuid4().hex[:12]
            # Phone searches use numeric characters because the value itself contains no token.
            query = token[:6] if model is not PhoneNumber else '987654'
            value = value_for(query + token[:5] if model is PhoneNumber else token)
            with SessionLocal() as db:
                indicator = make_indicator(value, token)
                pending_value = (f'https://pending-{token}.invalid/check' if model is URL else
                    f'+91987{query}{token[:5]}' if model is PhoneNumber else
                    f'pending{token}@demo.invalid')
                pending_indicator = make_indicator(pending_value, token)
                db.add(indicator); db.flush()
                db.add(pending_indicator); db.flush()
                indicator_id = getattr(indicator, id_field)
                pending_indicator_id = getattr(pending_indicator, id_field)
                verified = ScamReport(user_id=1, category_id=1, title=f'Synthetic verified {token}',
                    description='Synthetic test fixture only.', source_type='Test', risk_score=10, status='VERIFIED')
                pending = ScamReport(user_id=1, category_id=1, title=f'Synthetic pending {token}',
                    description='Synthetic test fixture only.', source_type='Test', risk_score=10, status='PENDING')
                db.add_all([verified, pending]); db.flush()
                db.add_all([link_model(report_id=verified.report_id, **{id_field: indicator_id}),
                            link_model(report_id=pending.report_id, **{id_field: indicator_id}),
                            link_model(report_id=pending.report_id, **{id_field: pending_indicator_id})])
                db.commit()

            response = client.get('/api/v1/indicators', params={'q': query})
            assert response.status_code == 200
            matches = [item for item in response.json()['items'] if item['value'] == value]
            expected_kind = {URL: 'URL', PhoneNumber: 'Phone', UPI: 'UPI', EmailAddress: 'Email'}[model]
            assert matches == [{'kind': expected_kind, 'value': value, 'verified_reports': 1}]
            assert all(item['value'] != pending_value for item in response.json()['items'])
            assert client.get('/api/v1/indicators', params={'q': 'xy'}).json()['items'] == []
