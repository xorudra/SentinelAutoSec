r"""Optional one-command installer for the external scanning tools.

SentinelAutoSec works out of the box; Nmap, Nuclei and OWASP ZAP are external
programs used by specific scan stages. This script removes the need for users
to install anything by hand:

- **Nuclei** is downloaded as a portable binary straight from the official
  GitHub releases and unpacked into ``tools\bin`` inside this project. No
  admin rights, no PATH changes, no package manager required.
- **OWASP ZAP** ships as an official Windows installer, so this script
  downloads the latest installer and launches it for you (one click; or pass
  ``--zap-silent`` to attempt a fully silent install).
- **Nmap** needs its official installer (Npcap drivers require elevated
  privileges), so this script downloads the right installer and launches it
  for you instead of leaving you to find it.

The dashboard detects tools in ``tools\bin`` automatically (see
``integrations/external/locate.py``), so nothing needs to go on PATH.

Usage:
    python setup_optional_tools.py                # install whatever is missing
    python setup_optional_tools.py --list         # only show current status
    python setup_optional_tools.py --nuclei-only  # only Nuclei
    python setup_optional_tools.py --zap-silent   # ZAP installer runs unattended
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS_BIN = ROOT / "tools" / "bin"
DOWNLOADS = ROOT / "tools" / "downloads"
GITHUB_API = "https://api.github.com/repos/{repo}/releases/latest"
USER_AGENT = "SentinelAutoSec-optional-tools-installer"

sys.path.insert(0, str(ROOT))

from integrations.external.locate import locate


def _latest_asset(repo: str, suffix: str) -> tuple[str, str]:
    """Return (asset_name, download_url) for the newest release asset ending with suffix."""
    url = GITHUB_API.format(repo=repo)
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name.lower().endswith(suffix.lower()):
            return name, asset["browser_download_url"]
    raise RuntimeError(f"No asset ending with '{suffix}' found in the latest {repo} release.")


def _download(url: str, destination: Path) -> Path:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f"==> Downloading {url}")
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as file:
        total = int(response.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            file.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r    {done / 1_048_576:6.1f} / {total / 1_048_576:.1f} MB", end="", flush=True)
    print()
    return destination


def install_nuclei() -> None:
    existing = locate("nuclei")
    if existing:
        print(f"==> Nuclei already available at: {existing}")
        return
    TOOLS_BIN.mkdir(parents=True, exist_ok=True)
    name, url = _latest_asset("projectdiscovery/nuclei", "windows_amd64.zip")
    with tempfile.TemporaryDirectory() as tmp:
        archive = _download(url, Path(tmp) / name)
        print(f"==> Extracting {name} -> {TOOLS_BIN}")
        with zipfile.ZipFile(archive) as zf:
            for member in zf.namelist():
                if member.lower().endswith(".exe"):
                    target = TOOLS_BIN / Path(member).name
                    target.write_bytes(zf.read(member))
                    print(f"    installed: {target}")
    result = locate("nuclei")
    print(f"==> Nuclei {'ready: ' + result if result else 'NOT detected (unexpected)'}")


def _run_installer(installer: Path, silent: bool) -> None:
    args = [str(installer)] + (["/S"] if silent else [])
    print(f"==> Launching installer: {installer.name}" + ("  (silent)" if silent else ""))
    try:
        subprocess.Popen(args, shell=False)
        if silent:
            print("==> Silent install started; it may take a few minutes.")
        else:
            print("==> Click through the installer window when it appears.")
    except OSError as exc:
        print(f"    Could not start installer automatically ({exc}).")
        print(f"    Run it manually: {installer}")


def install_zap(silent: bool = False) -> None:
    if locate("zap.bat") or locate("ZAP.exe") or locate("zap.sh"):
        print("==> OWASP ZAP already installed; skipping download.")
        return
    name, url = _latest_asset("zaproxy/zaproxy", "windows.exe")
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    installer = _download(url, DOWNLOADS / name)
    _run_installer(installer, silent=silent)
    print("==> After the installer finishes, restart the dashboard.")


def install_nmap() -> None:
    if locate("nmap"):
        print(f"==> Nmap already available at: {locate('nmap')}")
        return
    name, url = _latest_asset("nmap/nmap", "setup.exe")
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    installer = _download(url, DOWNLOADS / name)
    _run_installer(installer, silent=False)
    print("==> After the installer finishes, restart the dashboard.")


def show_status() -> None:
    for label, names in (
        ("Nmap", ("nmap",)),
        ("Nuclei", ("nuclei",)),
        ("OWASP ZAP", ("zap-baseline.py", "zap.sh", "zap.bat", "ZAP.exe")),
    ):
        found = next((p for name in names if (p := locate(name))), None)
        print(f"    {label:10} {'available: ' + found if found else 'not found'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="only show current tool status")
    parser.add_argument("--nuclei-only", action="store_true", help="skip Nmap and ZAP")
    parser.add_argument("--zap-silent", action="store_true", help="run the ZAP installer unattended (/S)")
    parser.add_argument("--skip-zap", action="store_true", help="do not offer the ZAP installer")
    args = parser.parse_args()

    print("=" * 60)
    print("SentinelAutoSec - optional tools installer")
    print("=" * 60)
    print("Current status:")
    show_status()

    if args.list:
        return 0

    print()
    try:
        install_nuclei()
        if not args.nuclei_only:
            install_nmap()
            if not args.skip_zap:
                install_zap(silent=args.zap_silent)
    except Exception as exc:  # noqa: BLE001 - installer must always exit cleanly
        print(f"\nERROR: {exc}")
        print("Check your internet connection and try again.")
        return 1

    print()
    print("Done. Restart the dashboard (python launch_dashboard.py) to refresh the tool chips.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())