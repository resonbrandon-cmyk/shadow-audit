from pathlib import Path
import math
import re
from .base import Scanner, Finding

PATTERNS = {
    'OpenAI API key': r'\bsk-[A-Za-z0-9_-]{16,}\b',
    'AWS access key': r'\bAKIA[0-9A-Z]{16}\b',
    'GitHub token': r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b',
    'Google API key': r'\bAIza[0-9A-Za-z_-]{20,}\b',
    'Slack token': r'\bxox[baprs]-[0-9A-Za-z-]{12,}\b',
    'Stripe secret': r'\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b',
    'Bearer token': r'(?i)bearer\s+[A-Za-z0-9._~-]{20,}',
}

def redact(value: str) -> str:
    return value if len(value) < 10 else value[:4] + '…' + value[-4:]

def entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())

class CredentialScanner(Scanner):
    name = 'credentials'

    def scan(self, source: Path | str) -> list[Finding]:
        root = Path(source)
        files = [root] if root.is_file() else [path for path in root.rglob('*') if path.is_file() and path.stat().st_size < 2_000_000]
        findings = []
        for path in files:
            try:
                lines = path.read_text(errors='ignore').splitlines()
            except OSError:
                continue
            for line_number, line in enumerate(lines, 1):
                for kind, pattern in PATTERNS.items():
                    for match in re.finditer(pattern, line):
                        value = match.group(0)
                        if len(value) >= 16 and entropy(value.replace('Bearer ', '')) < 2.5:
                            continue
                        findings.append(Finding('Critical', f'{kind} detected', 'A credential-like value was found in scanned content.', {'path': str(path), 'line': line_number, 'pattern': kind, 'preview': redact(value)}, 'Revoke and rotate the credential, then remove it from source history.'))
        return findings
