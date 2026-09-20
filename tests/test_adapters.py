from integrations.external.nuclei import available as nuclei_available
from integrations.external.zap import available as zap_available
from security.scope_guard import ensure_explicit_http_target


def test_external_adapter_availability_is_boolean():
    assert isinstance(nuclei_available(), bool)
    assert isinstance(zap_available(), bool)


def test_external_guard_rejects_non_http():
    try:
        ensure_explicit_http_target("ftp://127.0.0.1:21")
    except ValueError:
        pass
    else:
        raise AssertionError("non-http target accepted")
