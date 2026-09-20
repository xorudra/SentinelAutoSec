# Local Lab

The included Flask application is intentionally bound through Docker Compose to `127.0.0.1:8080`.

```bash
docker compose -f lab/docker-compose.yml up -d --build
python -m apps.cli.main init
python -m apps.cli.main target add local-lab --url http://127.0.0.1:8080 --authorized
python -m apps.cli.main target scope-add local-lab 127.0.0.1 8080
python -m apps.cli.main scan local-lab
python -m apps.cli.main report --fmt html
```

Stop the lab with:

```bash
docker compose -f lab/docker-compose.yml down
```
