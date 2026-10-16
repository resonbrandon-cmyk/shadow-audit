from html import escape
import os, json, uuid, sqlite3, shutil
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from scanners.credentials import CredentialScanner
from scanners.shadow_ai import ShadowAIScanner
from scanners.oauth import OAuthScanner
from scanners.nhi import NHIScanner
from scanners.public_exposure import PublicExposureScanner
from reporting.generator import write_reports, findings_csv

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("DATABASE_PATH", ROOT / "data/shadow_audit.db")); DATA.parent.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="Shadow Audit")
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")
SCANNERS = {"credentials": CredentialScanner, "creds": CredentialScanner, "shadow_ai": ShadowAIScanner, "oauth": OAuthScanner, "nhi": NHIScanner, "public_exposure": PublicExposureScanner}
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024

def db():
    connection = sqlite3.connect(DATA); connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, client TEXT, scope TEXT DEFAULT '', modules TEXT DEFAULT '[]', created TEXT, status TEXT, findings TEXT, report_md TEXT, report_pdf TEXT, report_json TEXT)")
    for column, definition in (("scope", "TEXT DEFAULT ''"), ("modules", "TEXT DEFAULT '[]'"), ("report_json", "TEXT")):
        try: connection.execute(f"ALTER TABLE audits ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError: pass
    connection.commit(); return connection

def row_payload(row):
    findings = json.loads(row["findings"] or "[]")
    return {"audit_id": row["id"], "client": row["client"], "scope": row["scope"] or "", "modules": json.loads(row["modules"] or "[]"), "created": row["created"], "status": row["status"], "findings": findings, "finding_count": len(findings)}

@app.get("/", response_class=HTMLResponse)
def home():
    rows = db().execute("SELECT * FROM audits ORDER BY created DESC").fetchall()
    total = len(rows); completed = sum(row["status"] == "completed" for row in rows); finding_count = sum(len(json.loads(row["findings"] or "[]")) for row in rows)
    items = "".join(f'''<a class="audit-row" href="/audits/{r["id"]}"><div><strong>{escape(r["client"])}</strong><div class="muted">{escape(r["scope"] or "No scope specified")}</div></div><div><span class="badge">{escape(r["status"])}</span><span class="muted"> {len(json.loads(r["findings"] or "[]"))} findings</span></div></a>''' for r in rows)
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Shadow Audit · Dashboard</title><link rel="stylesheet" href="/static/styles.css"></head><body><div class="shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">◈</span> Shadow Audit</div><p class="nav-label">Workspace</p><a class="nav-link active" href="/">Dashboard</a><a class="nav-link" href="#new-audit">New audit</a></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Security operations</p><h1>Audit dashboard</h1><p class="muted">Detect exposure before it becomes an incident.</p></div><a class="button" href="#new-audit">+ New audit</a></header><section class="grid stats"><div class="card"><span class="stat-label">Total audits</span><strong class="stat-value">{total}</strong></div><div class="card"><span class="stat-label">Completed</span><strong class="stat-value">{completed}</strong></div><div class="card"><span class="stat-label">Total findings</span><strong class="stat-value">{finding_count}</strong></div></section><section class="grid two-col"><div class="card"><p class="eyebrow">Recent activity</p><h2>Audits</h2><div class="audit-list">{items or '<p class="muted">No audits yet. Create your first audit to begin.</p>'}</div></div><div class="card" id="new-audit"><p class="eyebrow">Start assessment</p><h2>Create a new audit</h2><p class="muted">Upload exports or source files. Processing stays local to this deployment.</p><form action="/audits" method="post" enctype="multipart/form-data"><label>Client name</label><input name="client" placeholder="Acme SRL" required><label>Scope</label><input name="scope" placeholder="Internal SaaS and AI usage"><label>Scanner modules</label><input name="modules" value="credentials,shadow_ai,oauth,nhi"><label>Evidence files</label><input type="file" name="files" multiple required><button type="submit">Run audit →</button></form></div></section></main></div></body></html>'''

@app.post("/audits")
async def create_audit(client: str = Form(...), scope: str = Form(""), modules: str = Form(...), files: list[UploadFile] = File(...)):
    if not client.strip(): raise HTTPException(400, "Client is required")
    selected = list(dict.fromkeys(x.strip() for x in modules.split(",") if x.strip()))
    unknown = set(selected) - set(SCANNERS)
    if unknown: raise HTTPException(400, f"Unknown modules: {', '.join(sorted(unknown))}")
    aid = str(uuid.uuid4()); folder = ROOT / "data" / "audits" / aid; folder.mkdir(parents=True)
    paths = []
    for upload in files:
        name = Path(upload.filename or "input").name
        if name in {"", ".", ".."}: raise HTTPException(400, "Invalid filename")
        content = await upload.read()
        if len(content) > MAX_UPLOAD: raise HTTPException(413, "File too large")
        path = folder / name; path.write_bytes(content); paths.append(path)
    findings = []
    for module in selected:
        for path in paths: findings.extend(SCANNERS[module]().scan(path))
    md, pdf, report_json = write_reports(aid, client, findings, folder, scope, selected)
    connection = db(); connection.execute("INSERT INTO audits (id, client, scope, modules, created, status, findings, report_md, report_pdf, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (aid, client, scope, json.dumps(selected), datetime.now(timezone.utc).isoformat(), "completed", json.dumps([f.__dict__ for f in findings]), str(md), str(pdf), str(report_json))); connection.commit()
    return {"audit_id": aid, "findings": len(findings), "markdown": f"/audits/{aid}/report.md", "pdf": f"/audits/{aid}/report.pdf", "json": f"/audits/{aid}/report.json"}

@app.get("/audits/{aid}", response_class=HTMLResponse)
def audit(aid: str):
    row = db().execute("SELECT * FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    values = json.loads(row["findings"] or "[]")
    counts = {level: sum(item.get("severity") == level for item in values) for level in ("Critical", "High", "Medium", "Low")}
    finding_rows = "".join(f'''<div class="audit-row"><div><strong>{escape(item.get("title", "Finding"))}</strong><div class="muted">{escape(item.get("description", ""))}</div></div><span class="badge {"danger" if item.get("severity") == "Critical" else "warning" if item.get("severity") == "High" else ""}">{escape(item.get("severity", "Unknown"))}</span></div>''' for item in values)
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(row["client"])} · Shadow Audit</title><link rel="stylesheet" href="/static/styles.css"></head><body><div class="shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">◈</span> Shadow Audit</div><p class="nav-label">Workspace</p><a class="nav-link" href="/">Dashboard</a><a class="nav-link active" href="/audits/{aid}">Audit detail</a></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Audit detail</p><h1>{escape(row["client"])}</h1><p class="muted">{escape(row["scope"] or "Not specified")}</p></div><span class="badge">{escape(row["status"])}</span></header><section class="grid stats"><div class="card"><span class="stat-label">Critical</span><strong class="stat-value">{counts["Critical"]}</strong></div><div class="card"><span class="stat-label">High</span><strong class="stat-value">{counts["High"]}</strong></div><div class="card"><span class="stat-label">All findings</span><strong class="stat-value">{len(values)}</strong></div></section><section class="card"><div class="topbar"><div><p class="eyebrow">Deliverables</p><h2>Reports and evidence</h2></div><div class="actions"><a class="button" href="/audits/{aid}/report.pdf">Download PDF</a><a class="button secondary" href="/audits/{aid}/report.md">Markdown</a><a class="button secondary" href="/audits/{aid}/report.json">JSON</a><a class="button secondary" href="/audits/{aid}/findings.csv">CSV</a></div></div><div class="divider"></div><h2>Findings</h2><div class="audit-list">{finding_rows or '<p class="muted">No findings were detected.</p>'}</div><form method="post" action="/audits/{aid}/delete"><button type="submit">Delete audit data</button></form></section></main></div></body></html>'''

@app.get("/audits/{aid}/data")
def audit_data(aid: str):
    row = db().execute("SELECT * FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    return JSONResponse(row_payload(row))

@app.post("/audits/{aid}/delete")
def delete_audit(aid: str):
    row = db().execute("SELECT * FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    folder = ROOT / "data" / "audits" / aid
    if folder.exists(): shutil.rmtree(folder)
    connection = db(); connection.execute("DELETE FROM audits WHERE id = ?", (aid,)); connection.commit()
    return {"deleted": aid}

def report_file(aid, column, media_type):
    row = db().execute(f"SELECT {column} FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    return FileResponse(row[0], media_type=media_type)
@app.get("/audits")
def list_audits(q: str = Query(""), status: str = Query("")):
    query = "SELECT * FROM audits WHERE 1=1"
    params = []
    if q.strip(): query += " AND (client LIKE ? OR scope LIKE ?)"; params.extend([f"%{q.strip()}%", f"%{q.strip()}%"])
    if status.strip(): query += " AND status = ?"; params.append(status.strip())
    query += " ORDER BY created DESC"
    return {"audits": [row_payload(row) for row in db().execute(query, params).fetchall()]}

@app.get("/audits/{aid}/findings")
def findings(aid: str, severity: str = Query(""), status: str = Query("")):
    row = db().execute("SELECT * FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    values = json.loads(row["findings"] or "[]")
    if severity.strip(): values = [item for item in values if item.get("severity", "").lower() == severity.lower()]
    if status.strip(): values = [item for item in values if item.get("status", "open").lower() == status.lower()]
    return {"audit_id": aid, "findings": values, "count": len(values)}

@app.patch("/audits/{aid}/findings/{finding_id}")
def update_finding(aid: str, finding_id: int, status: str = Form(...)):
    if status not in {"open", "in_progress", "resolved", "accepted_risk"}: raise HTTPException(400, "Invalid status")
    connection = db(); row = connection.execute("SELECT findings FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    values = json.loads(row["findings"] or "[]")
    if finding_id < 1 or finding_id > len(values): raise HTTPException(404, "Finding not found")
    values[finding_id - 1]["status"] = status
    connection.execute("UPDATE audits SET findings = ? WHERE id = ?", (json.dumps(values), aid)); connection.commit()
    return {"audit_id": aid, "finding_id": finding_id, "status": status}

@app.get("/audits/{aid}/findings.csv")
def findings_csv_download(aid: str):
    row = db().execute("SELECT findings FROM audits WHERE id = ?", (aid,)).fetchone()
    if not row: raise HTTPException(404)
    content = findings_csv(json.loads(row["findings"] or "[]"))
    return Response(content, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={aid}-findings.csv"})

@app.get("/audits/{aid}/report.md")
def report_md(aid: str): return report_file(aid, "report_md", "text/markdown")
@app.get("/audits/{aid}/report.pdf")
def report_pdf(aid: str): return report_file(aid, "report_pdf", "application/pdf")
@app.get("/audits/{aid}/report.json")
def report_json(aid: str): return report_file(aid, "report_json", "application/json")

