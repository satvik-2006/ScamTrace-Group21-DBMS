"""Render ACTUAL live application HTML with WeasyPrint; not a browser screenshot."""
from pathlib import Path
import requests,re
from weasyprint import HTML,CSS
import fitz
ROOT=Path(__file__).resolve().parents[1]
out=ROOT/'docs'
s=requests.Session()
base='http://127.0.0.1:8765'

def render(name,path):
    r=s.get(base+path,timeout=10);r.raise_for_status()
    html=r.text.replace('href="/static/style.css"',f'href="file://{ROOT}/app/static/style.css"')
    html=html.replace('</head>','<style>@page {size: 1480px 1020px; margin: 0} body {background:white;} .wrap{max-width:1400px;} .hero{display:flex!important; min-height:435px!important;} .hero-text{width:57%!important;} .hero-visual{width:43%!important;min-height:435px!important;} .metrics{display:flex!important;} .metric{width:25%!important;} .split-section{display:flex!important;} .split-section>div{width:58%!important;} .split-section>aside{width:40%!important;} .report-mini{display:flex!important;} </style></head>',1)
    pdf=HTML(string=html,base_url=base).write_pdf()
    document=fitz.open(stream=pdf,filetype='pdf')
    for i,p in enumerate(document):
        if i==0:
            pix=p.get_pixmap(matrix=fitz.Matrix(1.15,1.15),alpha=False)
            pix.save(out/(name+'.png'))
            print(name,r.status_code,'page_count',len(document),'pixels',pix.width,pix.height)

def login():
    html=s.get(base+'/login').text
    csrf=re.search(r'name="csrf_token" value="([0-9a-f]+)"',html).group(1)
    r=s.post(base+'/login',data={'csrf_token':csrf,'email':'moderator@demo.test','password':'DemoPass123!'},allow_redirects=True)
    print('login',r.status_code)

for name,path in [('01_overview','/'),('02_public_reports','/reports'),('03_analytics','/analytics'),('04_indicator_lookup','/indicators?q=electricity')]:render(name,path)
login()
for name,path in [('05_moderation','/moderation'),('06_report_detail','/reports/4'),('07_new_report','/reports/new')]:render(name,path)
