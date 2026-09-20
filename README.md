# SentinelAutoSec

[![CI](https://github.com/xorudra/SentinelAutoSec/actions/workflows/ci.yml/badge.svg)](https://github.com/xorudra/SentinelAutoSec/actions/workflows/ci.yml)

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

## Requirements

- Python **3.12+**
- Optional: Docker (for the loopback lab), Nmap, Nuclei, OWASP ZAP (EXTENDED profile tools degrade gracefully when absent)

## Quick start

### One-line setup (no activation needed)

**Windows PowerShell:**

```powershell
python -m venv .venv; .venv\Scripts\python -m pip install -e ".[dev]"; .venv\Scripts\sentinelsec init
```

**Linux/macOS:**

```bash
python3 -m venv .venv && .venv/bin/python -m pip install -e ".[dev]" && .venv/bin/sentinelsec init
```

Afterwards, run any CLI command the same way, e.g. `.venv\Scripts\sentinelsec scan local-lab`
(Windows) or `.venv/bin/sentinelsec scan local-lab` (Linux/macOS). Or activate the venv once
(see steps 1–2 below) and just use `sentinelsec ...` directly.

### 1. Create and activate a virtual environment (Python 3.12+)

```bash
python -m venv .venv
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

> **Windows notes**
> - If PowerShell refuses activation with *"running scripts is disabled on this system"*, run
>   `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for this terminal session, or skip
>   activation entirely and invoke the venv binaries directly (see step 2).
> - If `python -m venv` opens the Microsoft Store instead, use `py -3.12 -m venv .venv`.

### 2. Install

```bash
pip install -e ".[dev]"
```

If the venv is not activated, call the venv's tools directly instead:

```powershell
# Windows (no activation required)
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

```bash
# Linux/macOS (no activation required)
.venv/bin/python -m pip install -e ".[dev]"
```

### 3. Initialize and register the lab target

```bash
sentinelsec init
sentinelsec target add local-lab --url http://127.0.0.1:8080 --authorized
sentinelsec target scope-add local-lab 127.0.0.1 8080
```

`python -m apps.cli.main ...` is always equivalent to `sentinelsec ...` (e.g.
`python -m apps.cli.main init`). If `sentinelsec` is not on `PATH`, invoke the venv binary directly:
`.venv\Scripts\sentinelsec.exe` (Windows) or `.venv/bin/sentinelsec` (Linux/macOS).

### Run the included lab

```bash
docker compose -f lab/docker-compose.yml up -d --build
sentinelsec scan local-lab
sentinelsec assessment status 1
sentinelsec findings --assessment-id 1
sentinelsec report --assessment-id 1 --fmt html
sentinelsec report --assessment-id 1 --fmt pdf
docker compose -f lab/docker-compose.yml down
```

If Docker is unavailable, use another HTTP service you own and explicitly scope its host/port.

## API / dashboard

```bash
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Open the dashboard at `http://127.0.0.1:8000/` and API docs at `/docs`.

For protected API routes, set `SENTINELSEC_API_KEY` and send `X-API-Key`. Keep the API on loopback for development; production deployments require a real identity/access-control layer and TLS termination.

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `SENTINELSEC_DB` | `sentinelsec.db` | SQLite database path |
| `SENTINELSEC_REPORTS` | `reports/generated` | Report output directory |
| `SENTINELSEC_API_KEY` | unset | Enables API-key auth (`X-API-Key`) on protected routes |
| `SENTINELSEC_HTTP_TIMEOUT` | `10` | HTTP/TLS request timeout (seconds) |
| `SENTINELSEC_JOB_HEARTBEAT` | `15` | Background job heartbeat interval (seconds) |
| `SENTINELSEC_JOB_STALE` | `120` | Age after which a non-heartbeating RUNNING job is considered stale and requeued |

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
pytest -q        # 52 unit tests
ruff check .     # lint
mypy .           # type check
python -m compileall -q .
```

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs `pytest` and `ruff check .` on every push and pull request. See `CONTRIBUTING.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `docs/API.md`.
