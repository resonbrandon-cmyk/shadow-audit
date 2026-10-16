from pathlib import Path
import csv
from .base import Scanner, Finding

AI_DOMAINS = {'openai.com','api.openai.com','anthropic.com','api.anthropic.com','generativelanguage.googleapis.com','ai.google.dev','mistral.ai','api.cohere.ai','perplexity.ai','huggingface.co'}

class ShadowAIScanner(Scanner):
    name = 'shadow_ai'
    def scan(self, source: Path | str) -> list[Finding]:
        path = Path(source)
        if path.suffix.lower() != '.csv':
            return []
        findings = []
        with path.open(newline='', encoding='utf-8-sig') as handle:
            for row in csv.DictReader(handle):
                domain = (row.get('domain') or row.get('host') or '').lower().strip()
                if domain in AI_DOMAINS or any(domain.endswith('.' + item) for item in AI_DOMAINS):
                    findings.append(Finding('Medium', f'Generative AI endpoint observed: {domain}', 'Network telemetry contains a connection to a known AI provider.', {'domain': domain, 'source': row.get('source_ip') or row.get('source_host'), 'timestamp': row.get('timestamp'), 'requests': row.get('requests'), 'bytes': row.get('bytes')}, 'Confirm the business purpose, approved data handling, and identity controls for this tool.'))
        return findings
