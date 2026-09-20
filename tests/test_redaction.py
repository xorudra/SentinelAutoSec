from security.redaction import redact


def test_redacts_authorization():
    assert "[REDACTED]" in redact("Authorization: Bearer secret")
    assert "secret" not in redact("Authorization: Bearer secret")
