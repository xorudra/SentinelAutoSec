# SentinelAutoSec

**Automated Security Testing for Authorized Environments**

SentinelAutoSec is a local-first, modular security assessment framework for controlled labs and explicitly authorized environments. It provides a complete safe assessment workflow: authorization and scope enforcement, deterministic orchestration, durable checkpoint/resume, passive web/TLS analysis, optional Nmap discovery, optional Nuclei/ZAP baselines, structured evidence, findings/risk, audit logging, dashboard/API access, and reproducible reports.

> **Responsible use:** Only assess systems you own or are explicitly authorized to test. SentinelAutoSec deliberately excludes unrestricted autonomous exploitation, credential theft, persistence, lateral movement, exfiltration, stealth/evasion, and arbitrary AI command execution.

## What is implemented

- Explicit authorization gate and allow/exclude scope.
- Wildcard and malformed target rejection.
- Safe staged orchestration with durable SQLite checkpoints.
- Persistent background job state and startup recovery for queued/running jobs.
- Passive HTTP security-header, cookie, redirect and transport checks.
- TLS version, cipher and certificate-expiry inspection.
- Optional Nmap service/version discovery with fixed subprocess arguments.
- Optional Nuclei and OWASP ZAP baseline adapters under the `EXTENDED` profile.
- Fingerprinted/deduplicated findings and structured evidence.
- Severity/confidence risk scoring.
- Asset/service inventory.
- Audit log.
- FastAPI REST API, OpenAPI docs and local dashboard.
- API-key protection when `SENTINELSEC_API_KEY` is configured.
- Markdown, JSON, HTML and PDF reports.
- Loopback Docker lab.
- Unit tests, compile checks and GitHub CI.

See `docs/PHASES.md` for the completion matrix.

## Quick start

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\\.venv\\Scripts\\Activate.ps1

pip install -e ".[dev]"
python -m apps.cli.main init
python -m apps.cli.main target add local-lab --url http://127.0.0.1:8080 --authorized
python -m apps.cli.main target scope-add local-lab 127.0.0.1 8080
```

### Run the included lab

```bash
docker compose -f lab/docker-compose.yml up -d --build
python -m apps.cli.main scan local-lab
python -m apps.cli.main assessment status 1
python -m apps.cli.main findings --assessment-id 1
python -m apps.cli.main report --assessment-id 1 --fmt html
python -m apps.cli.main report --assessment-id 1 --fmt pdf
docker compose -f lab/docker-compose.yml down
```

If Docker is unavailable, use another HTTP service you own and explicitly scope its host/port.

## API / dashboard

```bash
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Open the dashboard at `http://127.0.0.1:8000/` and API docs at `/docs`.

For protected API routes, set `SENTINELSEC_API_KEY` and send `X-API-Key`. Keep the API on loopback for development; production deployments require a real identity/access-control layer and TLS termination.

## Assessment profiles

- `SAFE`: core passive web/TLS checks plus optional Nmap discovery for explicitly scoped IP targets.
- `EXTENDED`: `SAFE` plus optional Nuclei misconfiguration/exposure and OWASP ZAP baseline adapters. If a tool is not installed, the stage is recorded as skipped rather than failing the assessment.

## Checkpoint and resume

Each stage records completed modules, pending modules and structured state in SQLite. If execution stops, `assessment resume <id>` continues from the latest checkpoint. Finding fingerprints and idempotent asset/service writes prevent duplicate records on recovery.

## Security model

The framework separates **authorization**, **scope**, **tool execution**, **evidence**, and **reporting**. External commands are built as argument arrays and never interpolated into a shell. Evidence redacts common credential-bearing headers. HTTP redirects are not followed automatically, preventing a redirect from silently moving assessment activity outside the original URL.

Any future AI component should analyze normalized evidence only. It must not authorize targets, alter scope, construct arbitrary commands, or execute offensive actions.

## Development

```bash
pytest -q
python -m compileall -q .
```

The GitHub workflow runs tests and compilation. See `CONTRIBUTING.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `docs/API.md`.
