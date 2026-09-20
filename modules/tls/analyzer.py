import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse


@dataclass
class TLSFinding:
    fingerprint: str
    title: str
    severity: str
    confidence: str
    category: str
    evidence: str
    remediation: str
    cwe: str


def analyze(url: str, timeout: float = 5) -> tuple[list[TLSFinding], dict]:
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        return [], {"checked": False, "reason": "not_https"}
    port = p.port or 443
    ctx = ssl.create_default_context()
    with (
        socket.create_connection((p.hostname, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=p.hostname) as s,
    ):
        version = s.version() or "UNKNOWN"
        cipher = s.cipher()
        cert: dict[str, Any] = s.getpeercert() or {}
    meta = {
        "checked": True,
        "host": p.hostname,
        "port": port,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "certificate_subject": str(cert.get("subject", "")),
        "certificate_issuer": str(cert.get("issuer", "")),
        "certificate_not_before": cert.get("notBefore"),
        "certificate_not_after": cert.get("notAfter"),
    }
    findings = []
    if version in {"TLSv1", "TLSv1.1", "SSLv3"}:
        fp = hashlib.sha256(f"{p.hostname}|tls-version|{version}".encode()).hexdigest()
        findings.append(
            TLSFinding(
                fp,
                "Obsolete TLS protocol version",
                "HIGH",
                "HIGH",
                "TLS Configuration",
                f"Server negotiated {version}.",
                "Disable obsolete protocol versions and require TLS 1.2+ (prefer TLS 1.3).",
                "CWE-326",
            )
        )
    if cipher and any(x in cipher[0].upper() for x in ("RC4", "3DES", "DES-CBC")):
        fp = hashlib.sha256(f"{p.hostname}|weak-cipher|{cipher[0]}".encode()).hexdigest()
        findings.append(
            TLSFinding(
                fp,
                "Weak TLS cipher suite",
                "MEDIUM",
                "HIGH",
                "TLS Configuration",
                f"Negotiated cipher: {cipher[0]}.",
                "Disable legacy/weak cipher suites and use modern AEAD ciphers.",
                "CWE-327",
            )
        )
    if cert.get("notAfter"):
        try:
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            if expiry < datetime.now(UTC):
                fp = hashlib.sha256(f"{p.hostname}|certificate-expired".encode()).hexdigest()
                findings.append(
                    TLSFinding(
                        fp,
                        "TLS certificate is expired",
                        "HIGH",
                        "HIGH",
                        "TLS Configuration",
                        f"Certificate expiry: {cert['notAfter']}.",
                        "Renew the certificate and deploy a currently valid chain.",
                        "CWE-295",
                    )
                )
        except ValueError:
            pass
    return findings, meta
