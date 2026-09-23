"""Command 2 — Launch the Web Dashboard.

Starts the SentinelAutoSec web dashboard (FastAPI + browser GUI), picks a
free port automatically and opens the dashboard in the default browser.
Press Ctrl+C to stop.

Usage:
    python launch_dashboard.py
"""

import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
TOOLS_BIN = ROOT / "tools" / "bin"


def venv_python() -> Path:
    return (
        VENV_DIR / "Scripts" / "python.exe"
        if sys.platform == "win32"
        else VENV_DIR / "bin" / "python"
    )


def free_port(start: int = 8000, attempts: int = 20) -> int:
    """Return the first free localhost port at or after `start`."""
    for port in range(start, start + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    return start


def main() -> int:
    python = venv_python()
    if not python.exists():
        print("Environment is not set up yet.")
        print("Run this first:  python setup_environment.py")
        return 1

    port = free_port()
    url = f"http://127.0.0.1:{port}/"

    print("=" * 60)
    print("SentinelAutoSec - Web Dashboard")
    print("=" * 60)
    print(f"==> Dashboard URL : {url}")
    print("==> Stop with Ctrl+C")

    # Make project-local tools (downloaded by setup_optional_tools.py) visible
    # to the server process without requiring any manual PATH editing.
    env = os.environ.copy()
    if TOOLS_BIN.is_dir():
        env["PATH"] = f"{TOOLS_BIN}{os.pathsep}{env.get('PATH', '')}"

    process = subprocess.Popen(
        [
            str(python),
            "-m",
            "uvicorn",
            "apps.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(ROOT),
        env=env,
    )

    # Give the server a moment, then open the browser automatically.
    threading.Timer(2.0, lambda: webbrowser.open(url)).start()

    try:
        process.wait()
    except KeyboardInterrupt:
        print()
        print("==> Stopping dashboard ...")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        time.sleep(0.2)

    print("Dashboard stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
