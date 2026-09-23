import subprocess

from integrations.external.locate import locate
from security.scope_guard import ensure_explicit_http_target


class NucleiUnavailable(RuntimeError):
    pass


def available() -> bool:
    return locate("nuclei") is not None


def baseline(url: str, timeout: int = 120) -> dict:
    ensure_explicit_http_target(url)
    command = locate("nuclei")
    if not command:
        raise NucleiUnavailable("Nuclei is not installed.")
    proc = subprocess.run(
        [
            command,
            "-u",
            url,
            "-tags",
            "misconfig,exposure",
            "-severity",
            "info,low,medium",
            "-jsonl",
            "-silent",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Nuclei failed.")
    return {"tool": "nuclei", "target": url, "output": proc.stdout[:200000]}
