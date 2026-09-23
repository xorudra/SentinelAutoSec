"""Locate external security tools without requiring users to edit PATH.

Resolution order:
1. The system PATH (via shutil.which).
2. Common Windows install locations (scoop, Go, Chocolatey, default installers).
3. The project-local ``tools/bin`` directory, which ``setup_optional_tools.py``
   fills automatically so end users never have to install anything manually.
"""

from pathlib import Path
from shutil import which

PROJECT_TOOLS_BIN = Path(__file__).resolve().parents[2] / "tools" / "bin"

_FALLBACK_DIRS = (
    PROJECT_TOOLS_BIN,
    Path.home() / "scoop" / "shims",
    Path.home() / "go" / "bin",
    Path("C:/ProgramData/chocolatey/bin"),
    Path("C:/Program Files/OWASP ZAP"),
    Path("C:/Program Files (x86)/Nmap"),
    Path("C:/Program Files/Nmap"),
)

_WIN_EXE_SUFFIXES = (".exe", ".bat", ".cmd")


def locate(name: str) -> str | None:
    """Return the absolute path of a tool, or None when it cannot be found."""
    found = which(name)
    if found:
        return found
    for directory in _FALLBACK_DIRS:
        candidate = directory / name
        if candidate.is_file():
            return str(candidate)
        if not candidate.suffix:
            for suffix in _WIN_EXE_SUFFIXES:
                candidate = directory / f"{name}{suffix}"
                if candidate.is_file():
                    return str(candidate)
    return None