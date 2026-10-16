import os
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
from .base import Finding, Scanner

class PublicExposureScanner(Scanner):
    name = "public_exposure"
    def scan(self, input_path: Path) -> list[Finding]:
        if os.getenv("ENABLE_PUBLIC_APIS", "false").lower() != "true":
            return []
        domains = [line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        findings = []
        for domain in domains:
            try:
                request = Request(f"https://crt.sh/?q={quote(domain)}&output=json", headers={"User-Agent": "shadow-audit/0.1"})
                with urlopen(request, timeout=10) as response:
                    body = response.read(1_000_000).decode("utf-8", errors="replace")
                if body and body != "[]":
                    findings.append(Finding("Certificate transparency exposure", "Low", "Public certificate records reveal infrastructure associated with the supplied domain.", {"domain": domain}, "Review discovered hostnames and remove unintended public services."))
            except Exception:
                continue
        return findings
