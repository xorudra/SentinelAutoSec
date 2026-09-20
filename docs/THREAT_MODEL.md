# Threat Model

## Assets
- Target authorization and scope records
- Assessment state/checkpoints
- Findings and evidence
- API access
- External scanner processes

## Threats and controls

| Threat | Control |
|---|---|
| Unauthorized target assessment | Authorization flag + mandatory explicit scope |
| Wildcard/ambiguous target | Host/URL validation rejects wildcard hosts |
| Scope bypass through redirect | HTTP analyzer does not follow redirects |
| Shell injection | External tools use argument arrays with `shell=False` |
| Credential leakage in evidence | Header redaction |
| Lost progress after interruption | Durable SQLite checkpoints |
| Duplicate findings | Fingerprint-based deduplication |
| API exposure | Optional API key; default documentation binds to loopback |
| AI overreach | No AI execution/authorization path in the core workflow |

## Residual risks

The framework is not a production multi-tenant security platform. For deployment beyond a trusted local machine, add TLS termination, strong identity/authentication, authorization per tenant, secrets management, rate limiting, database backups, structured logging, and OS/container isolation for external tools.
