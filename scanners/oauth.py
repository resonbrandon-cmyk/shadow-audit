import json
from pathlib import Path
import yaml
from .base import Finding, Scanner
class OAuthScanner(Scanner):
    name="oauth"
    def __init__(self, scopes_file="data/risky_oauth_scopes.yaml"):
        self.risky=set(yaml.safe_load(Path(scopes_file).read_text(encoding="utf-8")))
    def scan(self, input_path: Path) -> list[Finding]:
        if input_path.suffix.lower() not in {".json"}:
            return []
        try:
            data=json.loads(input_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        grants=data if isinstance(data,list) else data.get("grants",[]); out=[]
        for grant in grants:
            scopes=set(grant.get("scopes",[])); risky=sorted(scopes & self.risky)
            if risky or any("admin" in s.lower() or "directory" in s.lower() for s in scopes):
                out.append(Finding("Risky OAuth grant", "High", "An application has sensitive or administrative OAuth permissions.", {"app":grant.get("app") or grant.get("client_id"),"scopes":sorted(scopes),"risky_scopes":risky}, "Validate the app owner, reduce scopes, and revoke unused grants."))
        return out
