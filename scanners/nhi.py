import csv, json
from pathlib import Path
from .base import Finding, Scanner
class NHIScanner(Scanner):
    name="nhi"
    def scan(self, input_path: Path) -> list[Finding]:
        if input_path.suffix.lower() not in {".csv", ".json"}:
            return []
        if input_path.suffix.lower()==".csv":
            with input_path.open(newline="", encoding="utf-8-sig") as f: rows=list(csv.DictReader(f))
        else:
            data=json.loads(input_path.read_text(encoding="utf-8")); rows=data if isinstance(data,list) else data.get("identities",[])
        out=[]
        for row in rows:
            flags=[]
            if not row.get("owner"): flags.append("no owner")
            if not row.get("last_used"): flags.append("no last-used date")
            rotation_days=str(row.get("rotation_days") or "0")
            if rotation_days.isdigit() and int(rotation_days)>90: flags.append("rotation overdue")
            if "*" in str(row.get("permissions","")) or "admin" in str(row.get("permissions","")).lower(): flags.append("broad privilege")
            if flags: out.append(Finding("Non-human identity control gap", "High" if "broad privilege" in flags else "Medium", ", ".join(flags)+".", {"identity":row.get("name") or row.get("id"),"flags":flags}, "Assign an owner, remove excess privilege, and enforce rotation."))
        return out
