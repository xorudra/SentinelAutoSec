# API

Run locally:

```bash
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

If `SENTINELSEC_API_KEY` is configured, protected routes require `X-API-Key`.

Core routes:

- `GET /health`
- `GET /tools`
- `POST /targets`
- `GET /targets`
- `POST /targets/{id}/scope`
- `POST /assessments`
- `POST /assessments/{id}/start?background=true|false`
- `POST /assessments/{id}/resume`
- `GET /assessments`
- `GET /assessments/{id}/checkpoint`
- `GET /findings`
- `GET /findings/{id}`
- `GET /evidence`
- `GET /assets`
- `GET /audit-logs`
- `POST /reports?assessment_id=1&fmt=html`
- `GET /docs`

Keep the server bound to loopback unless you add a production authentication/reverse-proxy layer.
