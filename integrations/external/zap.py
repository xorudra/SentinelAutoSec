import shutil
import subprocess

from security.scope_guard import ensure_explicit_http_target


class ZAPUnavailable(RuntimeError):
    pass


def available() -> bool:
    return shutil.which("zap-baseline.py") is not None or shutil.which("zap.sh") is not None


def baseline(url: str, timeout: int = 180) -> dict:
    ensure_explicit_http_target(url)
    command = shutil.which("zap-baseline.py") or shutil.which("zap.sh")
    if not command:
        raise ZAPUnavailable("OWASP ZAP baseline command is not installed.")
    if command.endswith("zap-baseline.py"):
        args = [command, "-t", url, "-J", "-", "-m", "3"]
    else:
        args = [command, "-cmd", "-quickurl", url, "-quickprogress", "-quickout", "-"]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    # ZAP may return non-zero when alerts exist; preserve output rather than treating it as a crash.
    return {
        "tool": "owasp-zap-baseline",
        "target": url,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-200000:],
        "stderr": proc.stderr[-20000:],
    }
