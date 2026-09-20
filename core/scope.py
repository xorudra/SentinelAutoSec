from urllib.parse import urlparse

from database.models import Target
from security.validation import ScopeError, in_scope, validate_host, validate_url


def validate_target_for_scan(target: Target) -> None:
    if not target.authorization_status:
        raise ScopeError("Target is not marked as authorized.")
    if not target.scopes:
        raise ScopeError("Target has no explicit scope.")
    if all(s.excluded for s in target.scopes):
        raise ScopeError("Target scope contains no allowed entries.")


def validate_request(target: Target, host: str, port: int | None) -> None:
    validate_target_for_scan(target)
    host = validate_host(host)
    allowed_hosts = {s.host for s in target.scopes if not s.excluded}
    allowed_ports = {s.port for s in target.scopes if not s.excluded and s.port is not None}
    excluded_hosts = {s.host for s in target.scopes if s.excluded}
    if host.lower() in {h.lower() for h in excluded_hosts}:
        raise ScopeError(f"Blocked by scope exclusion: {host}:{port or '*'}")
    if not in_scope(host, port, allowed_hosts, allowed_ports):
        raise ScopeError(f"Blocked by scope: {host}:{port or '*'}")


def validate_target_url(target: Target) -> tuple[str, str, int]:
    if not target.url:
        raise ScopeError("Target requires a URL for web/TLS assessment.")
    url = validate_url(target.url)
    p = urlparse(url)
    return url, p.hostname or "", p.port or (443 if p.scheme == "https" else 80)
