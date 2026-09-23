# Changelog

## 1.1.0
- **GUI-only edition.** The command-line interface (`apps.cli`, the `sentinelsec` entry point and the `typer`/`rich` dependencies) has been removed; every workflow is available from the web dashboard.
- Added `python setup_environment.py` — one command to create the virtual environment, install dependencies and initialize the database.
- Added `python launch_dashboard.py` — one command to start the dashboard on a free port and open it in the browser.
- The dashboard is now a full control panel: add targets, manage scope, create/start/resume assessments with live progress, browse findings with evidence/remediation detail, and generate or open reports.
- Added `GET /reports/view` to render generated reports (HTML/PDF/JSON/Markdown) in the browser.
- Updated README and documentation for the two-command workflow.

## 1.0.0
- Completed authorized assessment workflow.
- Added durable checkpoint/resume and persisted background jobs.
- Added HTTP/TLS/Nmap assessment modules.
- Added optional Nuclei and OWASP ZAP baseline adapters for EXTENDED profile.
- Added assets, services, evidence and audit-log API views.
- Added HTML/PDF/JSON/Markdown reporting.
- Added local dashboard and API-key protection.
- Added scope exclusions and stricter redirect behavior.
- Added completion matrix and operational documentation.
