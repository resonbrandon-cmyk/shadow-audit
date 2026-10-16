import json
from pathlib import Path
import click
from scanners.credentials import CredentialScanner
from scanners.shadow_ai import ShadowAIScanner
from scanners.oauth import OAuthScanner
from scanners.nhi import NHIScanner
from scanners.public_exposure import PublicExposureScanner
from reporting.generator import write_reports
SCANNERS={"credentials":CredentialScanner,"creds":CredentialScanner,"shadow_ai":ShadowAIScanner,"oauth":OAuthScanner,"nhi":NHIScanner,"public_exposure":PublicExposureScanner}
@click.group()
def main(): pass
@main.command()
@click.option("--client", required=True)
@click.option("--scope", default="Not specified")
@click.option("--modules", required=True)
@click.option("--input", "input_dir", type=click.Path(exists=True, path_type=Path), required=True)
def run(client,scope,modules,input_dir):
    selected=list(dict.fromkeys(x.strip() for x in modules.split(",") if x.strip()))
    unknown=set(selected)-set(SCANNERS)
    if unknown: raise click.ClickException(f"Unknown modules: {', '.join(sorted(unknown))}")
    paths=[p for p in input_dir.rglob("*") if p.is_file()] if input_dir.is_dir() else [input_dir]
    findings=[]
    for module in selected:
        for path in paths: findings.extend(SCANNERS[module]().scan(path))
    aid=client.lower().replace(" ","-"); folder=Path("data/audits")/aid
    md,pdf,report_json=write_reports(aid,client,findings,folder,scope,selected)
    click.echo(json.dumps({"audit_id":aid,"findings":len(findings),"markdown":str(md),"pdf":str(pdf),"json":str(report_json)},indent=2))
@main.command()
@click.option("--audit-id", required=True)
@click.option("--format", "fmt", type=click.Choice(["pdf","md","json"]), default="pdf")
def report(audit_id,fmt): click.echo(str(Path("data/audits")/audit_id/f"report.{fmt}"))
@main.command(name="list")
def list_audits():
    root=Path("data/audits")
    rows=[]
    if root.exists():
        for folder in sorted(root.iterdir()):
            report_file=folder/"report.json"
            if report_file.exists():
                data=json.loads(report_file.read_text(encoding="utf-8"))
                rows.append({"audit_id":data.get("audit_id"),"client":data.get("client"),"risk_score":data.get("risk_score"),"findings":len(data.get("findings",[]))})
    click.echo(json.dumps(rows,indent=2))

if __name__=="__main__": main()
