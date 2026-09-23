# Local Lab

The included web application is intentionally bound through Docker Compose to `127.0.0.1:8080`.

```bash
docker compose -f lab/docker-compose.yml up -d --build
```

Then use the GUI workflow:

1. `python setup_environment.py` (once) and `python launch_dashboard.py`
2. In the dashboard, add target `local-lab` with URL `http://127.0.0.1:8080` (Authorized checked).
3. Add scope: host `127.0.0.1`, port `8080` — or leave the port empty to scan all ports (slower).
4. Create an assessment and press **Start**.
5. Watch findings appear, then generate/open reports from the assessment row.

Stop the lab with:

```bash
docker compose -f lab/docker-compose.yml down
```
