from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass
class Finding:
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ''

class Scanner:
    name = 'base'
    def scan(self, source: Path | dict | list) -> list[Finding]:
        raise NotImplementedError
