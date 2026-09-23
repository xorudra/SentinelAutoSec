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

## Quick start — just two commands

### Command 1 · Setup Environment

```bash
python setup_environment.py
```

Creates the `.venv` virtual environment, installs all dependencies and initializes the SQLite database. Safe to re-run at any time.

### Command 2 · Launch the Web Dashboard

```bash
python launch_dashboard.py
```

Starts the dashboard on a free local port (`127.0.0.1`), opens it in your browser, and keeps it running until you press `Ctrl+C`.

> If `python` opens the Microsoft Store instead, use `py` instead of `python` (e.g. `py setup_environment.py`).

### Using the dashboard (everything is GUI from here)

1. **Add a target** — Targets section: name + URL (e.g. `http://127.0.0.1:8080`), keep *Authorized* checked, click **Add target**.
2. **Add scope** — mandatory: pick the target, enter host and port. **Leave Port empty to allow and scan ALL ports (1–65535) with Nmap** (slower); enter a specific port to limit the scan. Click **Add scope entry**.

> **Lab data:** lab targets (e.g. the bundled `local-lab` demo) are hidden by default — the dashboard shows only your own scans. Use the **Include lab data** switch at the top of the page to view lab results, and "Mark lab / Unmark lab" on any target row to change its lab status.
3. **Create assessment** — pick the target and a profile (`SAFE`/`EXTENDED`), click **Create assessment**.
4. **Start** — click **Start** in the assessment row; status and progress refresh automatically every few seconds.
5. **Inspect findings** — the Findings table updates live; click a row to see evidence and remediation.
6. **Reports** — click **Report** to generate, **Open** to view the HTML report in a new tab (Markdown/JSON/HTML/PDF are generated).

### Optional: scan the included loopback lab

```bash
docker compose -f lab/docker-compose.yml up -d --build
```

Then add `http://127.0.0.1:8080` as a target in the dashboard (scope host `127.0.0.1`, port `8080`) and start an assessment. Stop the lab with `docker compose -f lab/docker-compose.yml down`. If Docker is unavailable, use any HTTP service you own and scope its host/port.

## Direct API access (optional)

Everything in the dashboard is a thin layer over a documented REST API: OpenAPI docs at `/docs` and ReDoc at `/redoc`. For protected API routes, set `SENTINELSEC_API_KEY` and send `X-API-Key`. Keep the API on loopback for development; production deployments require a real identity/access-control layer and TLS termination.

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `SENTINELSEC_DB` | `sentinelsec.db` | SQLite database path |
| `SENTINELSEC_REPORTS` | `reports/generated` | Report output directory |
| `SENTINELSEC_API_KEY` | unset | Enables API-key auth (`X-API-Key`) on protected routes |
| `SENTINELSEC_HTTP_TIMEOUT` | `10` | HTTP/TLS request timeout (seconds) |
| `SENTINELSEC_NMAP_TIMEOUT` | `900` | Max seconds for each Nmap phase (full-range scans are two-phase: discovery + version detection) |
| `SENTINELSEC_JOB_HEARTBEAT` | `15` | Background job heartbeat interval (seconds) |
| `SENTINELSEC_JOB_STALE` | `120` | Age after which a non-heartbeating RUNNING job is considered stale and requeued |

## Assessment profiles

- `SAFE`: core passive web/TLS checks plus optional Nmap discovery for explicitly scoped IP targets.
- `EXTENDED`: `SAFE` plus optional Nuclei misconfiguration/exposure and OWASP ZAP baseline adapters. If a tool is not installed, the stage is recorded as skipped rather than failing the assessment.

### Installing the optional tools (Windows)

The dashboard chips show `available` / `not installed` by checking whether each tool is on your `PATH`. The optional tools are external programs, not pip packages:

| Tool | Install | Verify |
|---|---|---|
| **Nmap** | https://nmap.org/download.html (the installer adds it to PATH) | `nmap --version` |
| **Nuclei** | `scoop install nuclei` · `choco install nuclei` · or download `nuclei-windows-amd64.exe` from https://github.com/projectdiscovery/nuclei/releases, rename to `nuclei.exe` and place it in a folder on `PATH` | `nuclei -version` |
| **OWASP ZAP** | https://www.zaproxy.org/download/ (Windows installer) — then add the install folder (contains `zap.bat`) to `PATH` | `zap.bat -version` |

After installing, restart the dashboard (`python launch_dashboard.py`) so the availability chips refresh. On Linux/macOS the ZAP wrapper `zap-baseline.py`/`zap.sh` is detected instead.


## Checkpoint and resume

Each stage records completed modules, pending modules and structured state in SQLite. If execution stops, click **Resume** on the assessment in the dashboard (or `POST /assessments/{id}/resume`) to continue from the latest checkpoint. Finding fingerprints and idempotent asset/service writes prevent duplicate records on recovery.

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
