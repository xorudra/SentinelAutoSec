# Plugin Architecture

SentinelAutoSec keeps tool-specific execution behind small adapters. Adapters should:

1. expose `available()`;
2. validate the target before execution;
3. construct a fixed argument list (never a shell command string);
4. enforce a timeout;
5. return normalized structured evidence;
6. never make authorization decisions;
7. never receive arbitrary AI-generated command arguments.

Current adapters:

- `integrations/nmap/adapter.py` — service/version discovery.
- `integrations/external/nuclei.py` — optional misconfiguration/exposure baseline.
- `integrations/external/zap.py` — optional OWASP ZAP baseline.

External scanners are only used by the `EXTENDED` profile and are skipped when unavailable. Their output is stored as evidence; the core workflow remains usable without them.
