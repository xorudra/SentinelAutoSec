# Architecture

```text
Web Dashboard / REST API
          |
          v
  Authorization + Scope Gate
          |
          v
 Durable Assessment Orchestrator
   |       |        |        |
 HTTP     TLS      Nmap   Extended Baselines
   |       |        |        |
   +-------+--------+--------+
              |
       Assets / Services
              |
       Findings / Evidence
              |
        Risk + Audit Log
              |
       Markdown/JSON/HTML/PDF
```

## Design principles

1. **Authorization is a prerequisite**, not an AI/tool decision.
2. **Scope is explicit** and checked before assessment activity.
3. **External tools are optional** and invoked using fixed argument arrays without a shell.
4. **The database is the source of truth** for assessment state and checkpoints.
5. **Findings are deterministic and fingerprinted** to avoid duplicate records.
6. **Evidence is redacted where credential-like headers may appear.**
7. **AI, if added later, remains advisory** and cannot authorize targets or execute arbitrary commands.
