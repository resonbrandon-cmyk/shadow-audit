# Shadow Audit MVP

Local-first audit tooling for Shadow AI usage, credential exposure, risky OAuth grants, non-human identity controls, and client-ready reports.

## Run with Docker

```powershell
Copy-Item .env.example .env
docker compose up --pull always --build
```

Open http://localhost:8000. Upload one or more input files, choose modules, and create an audit. Client data is persisted under `data/audits` and is not sent anywhere unless public integrations are added later.

## CLI

```powershell
python -m cli.main run --client "Acme SRL" --modules credentials,shadow_ai,oauth,nhi --input .\tests\sample_inputs
python -m cli.main report --audit-id acme-srl --format pdf
```

## Inputs

- Credentials: a file or directory; findings show only redacted previews.
- Shadow AI: CSV columns may include `timestamp`, `src_ip`, `domain`, `request_count`, and `bytes`; PCAP parsing is supported through Scapy.
- OAuth: JSON list or `{ "grants": [...] }` with `app`, `client_id`, and `scopes`.
- NHI: CSV or JSON list with `name`, `owner`, `last_used`, `rotation_days`, and `permissions`.

## Design decisions

The MVP uses SQLite, server-rendered HTML, local filesystem storage, and synchronous scan execution to minimize operational complexity. Public exposure checks are intentionally omitted from the first safe baseline because GitHub and HIBP access require careful authorization, rate limiting, and client consent; add them only behind explicit configuration and legal review.

## Added operator features

- Search and filter audits with `GET /audits?q=client&status=completed`.
- Filter findings with `GET /audits/<id>/findings?severity=High&status=open`.
- Update remediation status with `PATCH /audits/<id>/findings/<number>` using `status=open`, `in_progress`, `resolved`, or `accepted_risk`.
- Download findings as CSV from `/audits/<id>/findings.csv`.
- Download machine-readable reports from `/audits/<id>/report.json`.
- List generated CLI audits with `python -m cli.main list`.
- Delete an audit and its local files with `POST /audits/<id>/delete`.

