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
