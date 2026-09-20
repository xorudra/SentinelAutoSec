import hashlib
import re
from dataclasses import dataclass

import httpx

from security.redaction import redact


@dataclass
class WebFinding:
    fingerprint: str
    title: str
    severity: str
    confidence: str
    category: str
    evidence: str
    remediation: str
    cwe: str


SECURITY_HEADERS = {
    "x-content-type-options": ("Missing X-Content-Type-Options", "LOW", "CWE-693"),
    "content-security-policy": ("Missing Content-Security-Policy", "LOW", "CWE-693"),
    "referrer-policy": ("Missing Referrer-Policy", "LOW", "CWE-693"),
    "permissions-policy": ("Missing Permissions-Policy", "LOW", "CWE-693"),
}


def _fp(url: str, key: str) -> str:
    return hashlib.sha256(f"{url}|{key}".encode()).hexdigest()


def analyze(url: str, timeout: float = 10) -> tuple[list[WebFinding], dict]:
    with httpx.Client(
        follow_redirects=False, timeout=timeout, headers={"User-Agent": "SentinelAutoSec/1.0"}
    ) as client:
        response = client.get(url)
    headers = {k.lower(): v for k, v in response.headers.items()}
    final = response.url
    findings: list[WebFinding] = []
    for header, (title, severity, cwe) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                WebFinding(
                    _fp(str(final), header),
                    title,
                    severity,
                    "HIGH",
                    "Security Misconfiguration",
                    f"HTTP {response.status_code}; {header}: absent",
                    f"Configure {header} according to the application security requirements.",
                    cwe,
                )
            )
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookies = re.split(r"(?i)(?=\b(?:__Host-|__Secure-|[A-Za-z0-9_-]+)=)", set_cookie)
        if any("secure" not in c.lower() for c in cookies if c.strip()):
            findings.append(
                WebFinding(
                    _fp(str(final), "cookie-secure"),
                    "Cookie missing Secure attribute",
                    "MEDIUM",
                    "HIGH",
                    "Security Misconfiguration",
                    "A Set-Cookie response was observed without Secure.",
                    "Set Secure on cookies that should only travel over HTTPS.",
                    "CWE-614",
                )
            )
    if str(final).lower().startswith("http://") and final.host not in (
        "127.0.0.1",
        "localhost",
        "::1",
    ):
        findings.append(
            WebFinding(
                _fp(str(final), "https"),
                "Application served over HTTP",
                "MEDIUM",
                "HIGH",
                "Transport Security",
                "The final URL uses HTTP rather than HTTPS.",
                "Use HTTPS for production traffic and redirect HTTP to HTTPS.",
                "CWE-319",
            )
        )
    meta = {
        "status_code": response.status_code,
        "final_url": str(final),
        "headers": dict(response.headers),
        "content_length": len(response.content),
        "redirect_count": len(response.history),
    }
    return findings, {"headers": redact(str(meta)), "status_code": response.status_code}
