from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pathlib import Path
import uuid, json
from scanners.credentials import CredentialScanner
from scanners.shadow_ai import ShadowAIScanner
from scanners.oauth import OAuthScanner
from scanners.nhi import NHIScanner
from reporting.generator import generate_markdown

app = FastAPI(title='Shadow Audit')
ROOT = Path('/app') if Path('/app').exists() else Path('.')
UPLOADS, REPORTS = ROOT / 'uploads', ROOT / 'reports'
UPLOADS.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
AUDITS = {}
SCANNERS = {'credentials': CredentialScanner(), 'shadow_ai': ShadowAIScanner(), 'oauth': OAuthScanner(), 'nhi': NHIScanner()}

@app.get('/api/health')
def health(): return {'status': 'ok'}

@app.get('/', response_class=HTMLResponse)
def home():
    return '''<!doctype html><html><head><title>Shadow Audit</title><style>body{font:16px system-ui;max-width:850px;margin:40px auto;padding:0 20px;color:#182033}main{border:1px solid #ddd;border-radius:16px;padding:24px}input,select,button{padding:10px;margin:6px 0;width:100%}button{background:#315cff;color:white;border:0;border-radius:8px;font-weight:700}</style></head><body><main><h1>Shadow Audit</h1><p>Local Shadow AI and identity exposure assessment.</p><form action="/audits" method="post" enctype="multipart/form-data"><input name="client" placeholder="Client name" required><select name="module"><option value="credentials">Credential exposure</option><option value="shadow_ai">Shadow AI traffic</option><option value="oauth">OAuth grants</option><option value="nhi">Non-human identities</option></select><input type="file" name="input_file" required><button>Run audit</button></form></main></body></html>'''

@app.post('/audits')
async def create_audit(client: str = Form(...), module: str = Form(...), input_file: UploadFile = File(...)):
    audit_id = uuid.uuid4().hex
    path = UPLOADS / f'{audit_id}_{Path(input_file.filename or "input").name}'
    path.write_bytes(await input_file.read())
    findings = SCANNERS.get(module, SCANNERS['credentials']).scan(path)
    report = generate_markdown(client, findings, REPORTS / f'{audit_id}.md')
    AUDITS[audit_id] = {'client': client, 'module': module, 'findings': len(findings), 'report': str(report)}
    return {'audit_id': audit_id, 'findings': len(findings), 'report': f'/audits/{audit_id}/report'}

@app.get('/audits/{audit_id}')
def get_audit(audit_id: str): return AUDITS.get(audit_id, {'error': 'not found'})

@app.get('/audits/{audit_id}/report')
def get_report(audit_id: str): return FileResponse(REPORTS / f'{audit_id}.md', media_type='text/markdown', filename=f'{audit_id}.md')
