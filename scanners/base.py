from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

class Scanner:
    name = "base"
    def scan(self, input_path: Path) -> list[Finding]:
        raise NotImplementedError

def redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-4:]}"
