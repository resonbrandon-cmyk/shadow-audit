import csv, socket
from pathlib import Path
import yaml
from .base import Finding, Scanner

class ShadowAIScanner(Scanner):
    name="shadow_ai"
    def __init__(self, domains_file="data/known_ai_domains.yaml"):
        self.domains=yaml.safe_load(Path(domains_file).read_text(encoding="utf-8"))["ai_domains"]
    def scan(self, input_path: Path) -> list[Finding]:
        if input_path.suffix.lower() not in {".csv", ".pcap", ".pcapng", ".cap"}:
            return []
        rows=[]
        if input_path.suffix.lower()==".csv":
            with input_path.open(newline="", encoding="utf-8-sig") as f: rows=list(csv.DictReader(f))
        else:
            try:
                from scapy.all import rdpcap, IP, TCP, UDP
                for packet in rdpcap(str(input_path)):
                    if IP in packet:
                        rows.append({"timestamp":str(packet.time),"src_ip":packet[IP].src,"dst_ip":packet[IP].dst,"domain": "", "bytes":len(packet)})
            except Exception: return []
        findings=[]
        for row in rows:
            domain=(row.get("domain") or row.get("host") or "").lower()
            if any(domain==d or domain.endswith("."+d) for d in self.domains):
                findings.append(Finding("Generative AI endpoint observed", "Medium", "Network traffic matched a configured AI provider domain.", {"domain":domain,"source_ip":row.get("source_ip") or row.get("src_ip"),"timestamp":row.get("timestamp"),"request_count":row.get("request_count",1),"bytes":row.get("bytes",0)}, "Confirm business purpose, approved tools, and data-handling controls."))
        return findings
