import ipaddress
from urllib.parse import urlparse


class ScopeError(ValueError):
    pass


def validate_host(host: str) -> str:
    host = host.strip()
    if not host or len(host) > 255:
        raise ScopeError("Invalid host.")
    if host.lower() in {"0.0.0.0", "::", "*"}:
        raise ScopeError("Wildcard hosts are not allowed.")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        if any(c in host for c in "/\\ \t\r\n"):
            raise ScopeError("Invalid hostname.")
        return host


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only explicit http/https URLs are allowed.")
    validate_host(parsed.hostname)
    return url


def in_scope(
    host: str,
    port: int | None,
    allowed_hosts: set[str],
    allowed_ports: set[int],
    allow_all_ports: bool = False,
) -> bool:
    normalized = host.lower()
    host_ok = normalized in {h.lower() for h in allowed_hosts}
    port_ok = allow_all_ports or port is None or port in allowed_ports
    return host_ok and port_ok
