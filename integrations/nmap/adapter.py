import shutil
import subprocess
import xml.etree.ElementTree as ET


class NmapUnavailable(RuntimeError):
    pass


def available() -> bool:
    return shutil.which("nmap") is not None


def scan(host: str, ports: list[int], timeout: int = 30) -> list[dict]:
    if not available():
        raise NmapUnavailable("Nmap not found.")
    if not ports:
        return []
    port_arg = ",".join(str(p) for p in ports)
    proc = subprocess.run(
        ["nmap", "-sV", "-oX", "-", "-p", port_arg, host],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Nmap failed.")
    root = ET.fromstring(proc.stdout)
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
