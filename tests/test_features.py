from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from reporting.generator import write_reports
from scanners.base import Finding

ROOT=Path(__file__).parent/"sample_inputs"
client=TestClient(app)

def test_reports_include_json_and_summary(tmp_path):
    md,pdf,report_json=write_reports("test-id","Test Client",[Finding("Issue","High","Description",{},"Fix")],tmp_path,"Test scope",["credentials"])
    assert md.exists() and pdf.exists() and report_json.exists()
    data=report_json.read_text(encoding="utf-8")
    assert '"High": 1' in data and "Test scope" in data

def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "audit-dashboard" not in response.text
    assert "Audit dashboard" in response.text
    assert "/static/styles.css" in response.text
    assert client.get("/static/styles.css").status_code == 200

def test_audit_creation_and_json_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.ROOT", tmp_path)
    monkeypatch.setattr("app.main.DATA", tmp_path/"audit.db")
    response=client.post("/audits", data={"client":"Test Client","scope":"SaaS","modules":"credentials"}, files={"files":("fake.env", b"KEY=sk-1234567890abcdef_TEST_ONLY", "text/plain")})
    assert response.status_code == 200
    audit_id=response.json()["audit_id"]
    detail=client.get(f"/audits/{audit_id}/data")
    assert detail.status_code == 200 and detail.json()["scope"] == "SaaS"
    assert client.get(f"/audits/{audit_id}/report.json").status_code == 200
    assert client.get(f"/audits/{audit_id}/findings.csv").status_code == 200
    assert client.get(f"/audits/{audit_id}/findings?severity=Critical").status_code == 200
    assert client.patch(f"/audits/{audit_id}/findings/1", data={"status":"resolved"}).status_code == 200
    assert client.get(f"/audits/{audit_id}/findings?status=resolved").json()["count"] == 1
    assert client.post(f"/audits/{audit_id}/delete").status_code == 200
    assert client.get(f"/audits/{audit_id}/data").status_code == 404
