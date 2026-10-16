import math, re
from pathlib import Path
import yaml
from .base import Finding, Scanner, redact

class CredentialScanner(Scanner):
    name = "credentials"
    def __init__(self, patterns_file="data/secret_patterns.yaml"):
        self.patterns = yaml.safe_load(Path(patterns_file).read_text(encoding="utf-8"))
    def scan(self, input_path: Path) -> list[Finding]:
        findings=[]
        files = [p for p in input_path.rglob("*") if p.is_file()] if input_path.is_dir() else [input_path]
        for path in files:
            try: text=path.read_text(encoding="utf-8", errors="ignore")
            except OSError: continue
            for line_no, line in enumerate(text.splitlines(), 1):
                for pattern in self.patterns:
                    for match in re.finditer(pattern["regex"], line):
                        token=match.group(0)
                        entropy=len(set(token)) / max(len(token), 1)
                        if len(token) >= 16 and entropy >= 0.15:
                            findings.append(Finding("Potential secret exposed", "Critical", f"{pattern['name']} detected in a file.", {"path":str(path),"line":line_no,"pattern":pattern["name"],"preview":redact(token)}, "Revoke the credential, identify its owner, and move it to a managed secret store."))
        return findings
