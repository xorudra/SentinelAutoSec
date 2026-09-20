# SentinelAutoSec — Completion Matrix

This document maps the implemented product against the engineering phases used for the project build.

| Phase | Area | Status | Implementation |
|---|---|---|---|
| 1 | Project foundation | COMPLETE | Python package, configuration, CLI/API, SQLite |
| 2 | Authorization & scope | COMPLETE | Explicit authorization gate, allow/exclude scope, wildcard rejection |
| 3 | Assessment orchestration | COMPLETE | Deterministic staged orchestrator |
| 4 | Checkpoint/resume | COMPLETE | Durable SQLite checkpoints, completed/pending modules |
| 5 | Web assessment | COMPLETE | Passive HTTP headers, cookies, transport checks |
| 6 | TLS assessment | COMPLETE | Negotiated TLS version/cipher and certificate expiry checks |
| 7 | Network discovery | COMPLETE | Optional Nmap service/version discovery with fixed argument construction |
| 8 | Extended scanners | COMPLETE | Optional Nuclei misconfiguration/exposure and OWASP ZAP baseline adapters; skipped when unavailable |
| 9 | Findings/evidence | COMPLETE | Fingerprints, structured evidence, assets/services |
| 10 | Risk/correlation | COMPLETE | Severity/confidence risk scoring and fingerprint deduplication |
| 11 | Jobs/API | COMPLETE | Background execution, persistent job state, REST API |
| 12 | Dashboard | COMPLETE | Local FastAPI/Jinja dashboard |
| 13 | Reporting | COMPLETE | Markdown, JSON, HTML and PDF |
| 14 | Auditability | COMPLETE | Target/scope/assessment/report/failure audit records |
| 15 | Lab | COMPLETE | Loopback Docker demo target |
| 16 | Testing/CI | COMPLETE | Unit tests, compile check, GitHub CI configuration |
| 17 | Security architecture | COMPLETE | No shell interpolation, redaction, explicit scope, safe profiles |
| 18 | AI layer | INTENTIONALLY ADVISORY-ONLY | Core assessment does not delegate authorization or command execution to AI |

## Explicit non-goals

The project does not implement unrestricted autonomous exploitation, credential theft, persistence, lateral movement, exfiltration, stealth/evasion, or arbitrary AI-generated command execution.

## Operational definition of complete

The repository is considered complete for the defined safe product scope when a user can create an explicitly authorized target, define its scope, run/resume an assessment, collect structured evidence/findings, inspect assets/services, review audit records, and export reports from the CLI or API.
