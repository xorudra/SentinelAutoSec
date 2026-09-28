"""Locate external security tools without requiring users to edit PATH.

Resolution order:
1. The system PATH (via shutil.which).
2. Common Windows install locations (scoop, Go, Chocolatey, default installers).
3. The project-local ``tools/bin`` directory, which ``setup_optional_tools.py``
   fills automatically so end users never have to install anything manually.

Each probe walks PATH and stats ~30 fallback candidates, and ``GET /tools``
performs about ten probes per request, so results are memoized for
``_CACHE_TTL_SECONDS``. Call :func:`clear_cache` after installing or removing
a tool so the very next lookup reflects it (the dashboard installer does this
automatically when an install finishes).
"""

import time
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

# name -> (monotonic timestamp, resolved path or None)
_CACHE_TTL_SECONDS = 30.0
_CACHE: dict[str, tuple[float, str | None]] = {}


def clear_cache() -> None:
    """Drop memoized lookups so the next call re-resolves from disk."""
    _CACHE.clear()


def _resolve(name: str) -> str | None:
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


def locate(name: str) -> str | None:
    """Return the absolute path of a tool, or None when it cannot be found.

    Results (including misses) are cached for ``_CACHE_TTL_SECONDS`` seconds.
    """
    now = time.monotonic()
    hit = _CACHE.get(name)
    if hit is not None and now - hit[0] <= _CACHE_TTL_SECONDS:
        return hit[1]
    result = _resolve(name)
    _CACHE[name] = (now, result)
    return result