# Shadow Audit

Local, Docker-first MVP for Shadow AI and identity exposure audits.

## Run

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open http://localhost:8000. The API health endpoint is `/api/health`.

## CLI

```powershell
python -m cli.main run --client "Acme SRL" --modules credentials --input .\tests\sample_inputs\secrets.env
```

Supported modules: `credentials`, `shadow_ai`, `oauth`, and `nhi`. The public-exposure module is intentionally offline by default; external APIs should be enabled only after explicit client authorization.

## Inputs

Credential scans accept a file or directory. Shadow AI scans accept CSV columns such as `domain`, `source_ip`, `timestamp`, `requests`, and `bytes`. OAuth accepts a JSON list or `{ "grants": [] }`. NHI accepts CSV or JSON records.

Findings redact credential evidence. Client data remains in local mounted directories. Do not scan systems or data without written authorization.

## Tests

```powershell
python -m pytest -q
```
