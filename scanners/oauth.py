import json
from pathlib import Path
from .base import Scanner, Finding

RISKY = ('admin', 'drive', 'gmail.send', 'cloud-platform', 'full_access')

class OAuthScanner(Scanner):
    name = 'oauth'
    def scan(self, source: Path | str) -> list[Finding]:
        records = json.loads(Path(source).read_text())
        if isinstance(records, dict): records = records.get('grants', records.get('items', []))
        findings = []
        for grant in records:
            scopes = ' '.join(grant.get('scopes', [])) if isinstance(grant.get('scopes', []), list) else str(grant.get('scopes', ''))
            risky = [token for token in RISKY if token in scopes.lower()]
            if risky:
                findings.append(Finding('High', 'Risky OAuth grant', 'An application has one or more broad or sensitive OAuth scopes.', {'app': grant.get('app') or grant.get('application'), 'user': grant.get('user'), 'scopes': scopes, 'matched': risky}, 'Review business need, remove unused scopes, and revoke unapproved grants.'))
        return findings
