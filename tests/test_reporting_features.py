from pathlib import Path
from reporting.generator import findings_csv

def test_findings_csv():
    content=findings_csv([{"title":"Issue","severity":"High","status":"open","description":"Desc","recommendation":"Fix","evidence":{"path":"x"}}])
    assert "title,severity,status" in content
    assert "Issue,High,open" in content
