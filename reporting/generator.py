import csv
import io
import json
from pathlib import Path
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from scanners.base import Finding

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]

def summarize(findings: list[Finding]) -> dict[str, int]:
    return {severity: sum(f.severity == severity for f in findings) for severity in SEVERITIES}

def risk_score(counts: dict[str, int]) -> int:
    weights = {"Critical": 30, "High": 15, "Medium": 7, "Low": 2, "Informational": 0}
    return min(100, sum(counts.get(key, 0) * weight for key, weight in weights.items()))

def findings_csv(findings: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "status", "description", "recommendation", "evidence"])
    writer.writeheader()
    for index, finding in enumerate(findings, 1):
        writer.writerow({"id": index, "title": finding.get("title", ""), "severity": finding.get("severity", ""), "status": finding.get("status", "open"), "description": finding.get("description", ""), "recommendation": finding.get("recommendation", ""), "evidence": json.dumps(finding.get("evidence", {}), ensure_ascii=False)})
    return output.getvalue()

def write_reports(aid, client, findings: list[Finding], folder: Path, scope="Not specified", modules=None):
    folder.mkdir(parents=True, exist_ok=True)
    md, pdf, json_path = folder / "report.md", folder / "report.pdf", folder / "report.json"
    modules = modules or []
    normalized = [dict(f.__dict__, status="open") for f in findings]
    counts = summarize(findings)
    score = risk_score(counts)
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {"audit_id": aid, "client": client, "scope": scope, "modules": modules, "created": timestamp, "risk_score": score, "severity_counts": counts, "findings": normalized}
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# Shadow AI and Identity Exposure Audit — {client}", "", f"**Audit ID:** `{aid}`  ", f"**Created:** {timestamp}  ", f"**Scope:** {scope}  ", f"**Modules:** {', '.join(modules) or 'Not specified'}  ", f"**Risk score:** {score}/100", "", "## Executive Summary", f"The audit produced {len(findings)} finding(s). Review Critical and High findings first.", "", "## Severity Summary"]
    lines += [f"- **{severity}:** {counts[severity]}" for severity in SEVERITIES]
    lines += ["", "## Methodology", "Inputs were processed locally using the selected scanner modules. Evidence is redacted by default.", "", "## Findings"]
    for severity in SEVERITIES:
        group = [f for f in normalized if f["severity"] == severity]
        if group:
            lines += [f"### {severity}"]
            for index, finding in enumerate(group, 1):
                lines += [f"#### {index}. {finding['title']}", finding["description"], f"**Status:** {finding['status']}", f"**Evidence:** `{finding['evidence']}`", f"**Recommendation:** {finding['recommendation']}", ""]
    lines += ["## Recommendations", "Prioritize credential revocation, owner assignment, least privilege, and approved AI-tool policy.", "", "## Appendix", "Machine-readable JSON and CSV exports are available in the audit directory."]
    md.write_text("\n".join(lines), encoding="utf-8")
    pdf_canvas = canvas.Canvas(str(pdf), pagesize=A4); y = 800; pdf_canvas.setFont("Helvetica-Bold", 14); pdf_canvas.drawString(40, y, f"Shadow Audit — {client}"); y -= 28; pdf_canvas.setFont("Helvetica", 9)
    for line in lines:
        for chunk in [line[i:i + 105] for i in range(0, len(line), 105)] or [""]:
            if y < 40: pdf_canvas.showPage(); y = 800; pdf_canvas.setFont("Helvetica", 9)
            pdf_canvas.drawString(40, y, chunk.replace("#", "")); y -= 13
    pdf_canvas.save()
    (folder / "findings.csv").write_text(findings_csv(normalized), encoding="utf-8", newline="")
    return md, pdf, json_path
