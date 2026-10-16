from pathlib import Path
from datetime import datetime
from scanners.base import Finding

def generate_markdown(client: str, findings: list[Finding], output: Path) -> Path:
    score = sum({'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 3}.get(item.severity, 1) for item in findings)
    lines = [f'# Shadow AI and Identity Exposure Audit', f'**Client:** {client}', f'**Generated:** {datetime.utcnow().isoformat()}Z', f'**Risk score:** {min(score, 100)}/100', '', '## Executive Summary', f'{len(findings)} finding(s) were identified during the configured local assessment.', '', '## Findings']
    for index, finding in enumerate(findings, 1):
        lines += [f'### {index}. [{finding.severity}] {finding.title}', finding.description, '', '**Evidence:**', '```json', str(finding.evidence), '```', '', f'**Recommendation:** {finding.recommendation}', '']
    lines += ['## Methodology', 'The assessment used the enabled local scanner modules and redacted evidence by default.', '', '## Appendix', 'Raw metadata is retained in the audit workspace.']
    output.write_text('\n'.join(lines), encoding='utf-8')
    return output
