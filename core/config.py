import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path(os.getenv("SENTINELSEC_DB", "sentinelsec.db"))

    reports_dir: Path = Path(os.getenv("SENTINELSEC_REPORTS", "reports/generated"))

    api_key: str | None = os.getenv("SENTINELSEC_API_KEY") or None

    request_timeout: float = float(os.getenv("SENTINELSEC_HTTP_TIMEOUT", "10"))

    job_heartbeat_seconds: float = float(os.getenv("SENTINELSEC_JOB_HEARTBEAT", "15"))

    job_stale_seconds: float = float(os.getenv("SENTINELSEC_JOB_STALE", "120"))

    nmap_timeout: float = float(os.getenv("SENTINELSEC_NMAP_TIMEOUT", "900"))


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)
