import csv, json
from pathlib import Path
from .base import Scanner, Finding

class NHIScanner(Scanner):
    name = 'nhi'
    def scan(self, source: Path | str) -> list[Finding]:
        path = Path(source)
        if path.suffix.lower() == '.csv':
            with path.open(newline='', encoding='utf-8-sig') as handle: records = list(csv.DictReader(handle))
        else: records = json.loads(path.read_text())
        findings = []
        for item in records:
            problems = []
            if not item.get('owner'): problems.append('no owner')
            if not item.get('last_used'): problems.append('no last-used date')
            if str(item.get('rotated_days_ago', '')).isdigit() and int(item['rotated_days_ago']) > 90: problems.append('rotation older than 90 days')
            if '*' in str(item.get('permissions', '')): problems.append('wildcard permission')
            if problems: findings.append(Finding('High', 'Non-human identity governance gap', ', '.join(problems).capitalize() + '.', {'identity': item.get('name') or item.get('id'), 'issues': problems}, 'Assign an owner, reduce permissions, and rotate or disable stale credentials.'))
        return findings
