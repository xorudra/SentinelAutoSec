# Changelog

## Unreleased
- **Zero-friction external tools.** Added `integrations/external/locate.py`: tool lookup now checks `PATH` first, then common install locations (scoop shims, `go/bin`, Chocolatey, `Program Files` for Nmap/ZAP) and the project-local `tools\bin` folder — installed-but-"not installed" chip confusion is gone, and tools never need manual PATH editing.
- Added `python setup_optional_tools.py` — one command to install the optional external tools: auto-downloads the portable Nuclei binary into `tools\bin`, and fetches + launches the official Nmap / OWASP ZAP installers. `--list` shows the current status, already-installed tools are skipped.
- `setup_environment.py` now auto-downloads Nuclei (non-fatally) during setup, so the EXTENDED profile works without any manual install.
- `launch_dashboard.py` puts `tools\bin` on the server process `PATH` automatically.
- The `/tools` API endpoint now reports the resolved executable path for each tool, and the dashboard chips show it in their tooltip.
- Lab data hidden by default. Targets flagged as lab (e.g. the bundled `local-lab` demo target) are hidden from the dashboard — targets, assessments, findings, activity and the stat cards show your own scans only. A new "Include lab data" switch brings them back, and the choice is remembered per browser.
- Added `is_lab` flag on targets: a "Lab target" checkbox when creating a target, a per-target "Mark lab / Unmark lab" action, and `POST /targets/{id}/lab` on the API.
- Existing databases are migrated automatically and the existing `local-lab` target is tagged as lab data on first start.

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
