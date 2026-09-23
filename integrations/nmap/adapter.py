import shutil
import subprocess
import xml.etree.ElementTree as ET

from core.config import settings


class NmapUnavailable(RuntimeError):
    pass


def available() -> bool:
    return shutil.which("nmap") is not None


def _timeout() -> int:
    return max(30, int(settings.nmap_timeout))


def _port_arg(ports: list[int]) -> str:
    return ",".join(str(p) for p in ports)


def _run_nmap(host: str, args: list[str], timeout: int) -> list[dict]:
    proc = subprocess.run(
        ["nmap", *args, host],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Nmap failed.")
    return _parse_xml(proc.stdout)


def _parse_xml(stdout: str) -> list[dict]:
    root = ET.fromstring(stdout)
    results = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        results.append(
            {
                "port": int(port.attrib["portid"]),
                "protocol": port.attrib.get("protocol", "tcp").upper(),
                "name": service.attrib.get("name") if service is not None else None,
                "version": service.attrib.get("version") if service is not None else None,
            }
        )
    return results


def _chunked(ports: list[int], size: int = 100) -> list[list[int]]:
    return [ports[i : i + size] for i in range(0, len(ports), size)]


def scan(host: str, ports: list[int] | None = None, timeout: int | None = None) -> list[dict]:
    """Scan a host.

    With an explicit port list, a single version-detection pass covers those
    ports. Without ports (the "scan all ports" mode), a fast full-range
    discovery pass (-p- -T4) runs first, then service/version detection is
    applied in batches to the ports found open.
    """
    if not available():
        raise NmapUnavailable("Nmap not found.")
    effective_timeout = int(timeout) if timeout else _timeout()

    if ports:
        return _run_nmap(host, ["-sV", "-oX", "-", "-p", _port_arg(sorted(set(ports)))], effective_timeout)

    open_ports = _run_nmap(host, ["-p-", "-T4", "-oX", "-"], effective_timeout)
    if not open_ports:
        return []

    merged: dict[tuple[int, str], dict] = {}
    for chunk in _chunked(sorted(item["port"] for item in open_ports)):
        for item in _run_nmap(host, ["-sV", "-oX", "-", "-p", _port_arg(chunk)], effective_timeout):
            merged[(item["port"], item["protocol"])] = item
    return sorted(merged.values(), key=lambda r: r["port"])
