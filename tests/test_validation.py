import pytest

from security.validation import ScopeError, validate_host, validate_url


def test_valid_loopback():
    assert validate_host("127.0.0.1") == "127.0.0.1"


def test_wildcard_rejected():
    with pytest.raises(ScopeError):
        validate_host("0.0.0.0")


def test_url_validation():
    assert validate_url("http://127.0.0.1:8080").startswith("http://")


def test_bad_scheme():
    with pytest.raises(ScopeError):
        validate_url("ftp://127.0.0.1")


def test_newline_host_rejected():
    with pytest.raises(ScopeError):
        validate_host("127.0.0.1\nexample")
