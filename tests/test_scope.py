import pytest

from core.scope import validate_request
from database.models import Target, TargetScope
from security.validation import ScopeError


def test_scope_requires_authorization():
    t = Target(
        name="x", authorization_status=False, scopes=[TargetScope(host="127.0.0.1", port=8080)]
    )
    with pytest.raises(ScopeError):
        validate_request(t, "127.0.0.1", 8080)


def test_scope_blocks_wrong_port():
    t = Target(
        name="x", authorization_status=True, scopes=[TargetScope(host="127.0.0.1", port=8080)]
    )
    with pytest.raises(ScopeError):
        validate_request(t, "127.0.0.1", 8081)


def test_scope_exclusion_wins():
    t = Target(
        name="x",
        authorization_status=True,
        scopes=[
            TargetScope(host="127.0.0.1", port=8080),
            TargetScope(host="127.0.0.1", port=8080, excluded=True),
        ],
    )
    with pytest.raises(ScopeError):
        validate_request(t, "127.0.0.1", 8080)


def test_portless_scope_allows_any_port():
    t = Target(
        name="x", authorization_status=True, scopes=[TargetScope(host="127.0.0.1")]
    )
    validate_request(t, "127.0.0.1", 80)      # URL default port
    validate_request(t, "127.0.0.1", 443)     # HTTPS default port
    validate_request(t, "127.0.0.1", 99999)   # any other port


def test_portless_scope_is_host_specific():
    t = Target(
        name="x",
        authorization_status=True,
        scopes=[TargetScope(host="127.0.0.1")],
    )
    with pytest.raises(ScopeError):
        validate_request(t, "127.0.0.2", 8080)


def test_portless_scope_exclusion_wins():
    t = Target(
        name="x",
        authorization_status=True,
        scopes=[
            TargetScope(host="127.0.0.1"),
            TargetScope(host="127.0.0.1", excluded=True),
        ],
    )
    with pytest.raises(ScopeError):
        validate_request(t, "127.0.0.1", 8080)


def test_explicit_scope_still_blocks_other_ports():
    t = Target(
        name="x",
        authorization_status=True,
        scopes=[
            TargetScope(host="127.0.0.1"),
            TargetScope(host="127.0.0.1", port=22),
        ],
    )
    validate_request(t, "127.0.0.1", 80)
    validate_request(t, "127.0.0.1", 22)
