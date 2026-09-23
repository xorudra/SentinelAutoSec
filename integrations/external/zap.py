import os
import subprocess

from integrations.external.locate import locate
from security.scope_guard import ensure_explicit_http_target


class ZAPUnavailable(RuntimeError):
    pass


# Windows ships ZAP as zap.bat / ZAP.exe; Linux/macOS as zap-baseline.py / zap.sh.
_ZAP_COMMANDS = ("zap-baseline.py", "zap.sh", "zap.bat", "ZAP.exe")


def available() -> bool:
    return _zap_command() is not None


def _zap_command() -> str | None:
    for name in _ZAP_COMMANDS:
        found = locate(name)
        if found:
            return found
    return None


def baseline(url: str, timeout: int = 180) -> dict:
    ensure_explicit_http_target(url)
    command = _zap_command()
    if not command:
        raise ZAPUnavailable("OWASP ZAP baseline command is not installed.")
    if os.path.basename(command).lower() == "zap-baseline.py":
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
