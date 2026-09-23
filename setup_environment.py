"""Command 1 — Setup Environment.

Creates the local virtual environment, installs all dependencies and
initializes the database. Safe to run multiple times (it resumes where
it left off).

Usage:
    python setup_environment.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"


def venv_python() -> Path:
    """Return the interpreter inside the project virtual environment."""
    relative = "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    return VENV_DIR / relative


def run(command: list[str | Path]) -> None:
    print("==>", " ".join(str(part) for part in command))
    subprocess.run(
        [str(part) for part in command],
        cwd=str(ROOT),
        check=True,
    )


def main() -> int:
    print("=" * 60)
    print("SentinelAutoSec - Setup Environment")
    print("=" * 60)

    if not VENV_DIR.exists():
        print("==> Creating virtual environment (.venv) ...")
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
    else:
        print("==> Reusing existing virtual environment (.venv)")

    python = venv_python()

    print("==> Upgrading pip ...")
    run([python, "-m", "pip", "install", "--upgrade", "pip", "--quiet"])

    print("==> Installing dependencies ...")
    run([python, "-m", "pip", "install", "-e", str(ROOT), "--quiet"])

    print("==> Initializing database ...")
    run(
        [
            python,
            "-c",
            "from core.db import init_db, migrate_schema; init_db(); migrate_schema(); print('Database ready.')",
        ]
    )

    # Optional: fetch the portable Nuclei binary into tools\bin so the EXTENDED
    # profile works without any manual install. Never fails the setup.
    try:
        print("==> Checking optional security tools (Nuclei/Nmap/ZAP) ...")
        run([python, "setup_optional_tools.py", "--nuclei-only", "--skip-zap"])
        print("    Tip: run 'python setup_optional_tools.py' any time to install the")
        print("    optional Nmap/OWASP ZAP helpers (EXTENDED profile only; SAFE scans")
        print("    never need them).")
    except Exception:  # noqa: BLE001 - offline machines must still finish setup
        print("    Skipped (offline or download failed) - the dashboard works without it.")

    print()
    print("=" * 60)
    print("Setup complete.")
    print("Next step:  python launch_dashboard.py")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
