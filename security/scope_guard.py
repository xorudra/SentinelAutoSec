from urllib.parse import urlparse

from security.validation import validate_url


def ensure_explicit_http_target(url: str) -> None:
    """Reject ambiguous/non-web targets before optional external scanners run."""
    normalized = validate_url(url)
    p = urlparse(normalized)
    if p.hostname in {"0.0.0.0", "::", "*"}:
        raise ValueError("Wildcard targets are not allowed.")
