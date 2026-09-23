from integrations.external import zap
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


def test_zap_available_detects_windows_install(monkeypatch):
    # Windows ZAP installs provide zap.bat / ZAP.exe rather than zap.sh.
    monkeypatch.setattr(
        zap.shutil,
        "which",
        lambda name: r"C:\Program Files\OWASP ZAP\zap.bat" if name == "zap.bat" else None,
    )
    assert zap.available() is True
    assert zap._zap_command() == r"C:\Program Files\OWASP ZAP\zap.bat"


def test_zap_unavailable_when_no_command_found(monkeypatch):
    monkeypatch.setattr(zap.shutil, "which", lambda name: None)
    assert zap.available() is False


def test_zap_prefers_baseline_wrapper(monkeypatch):
    monkeypatch.setattr(
        zap.shutil,
        "which",
        lambda name: "/usr/bin/zap-baseline.py" if name == "zap-baseline.py" else None,
    )
    assert zap._zap_command() == "/usr/bin/zap-baseline.py"


def test_zap_baseline_uses_cmd_flags_for_windows_zap(monkeypatch):
    captured = {}

    class _Proc:
        returncode = 0
        stdout = "alerts"
        stderr = ""

    def fake_run(args, **kwargs):
        captured["args"] = args
        return _Proc()

    monkeypatch.setattr(
        zap.shutil,
        "which",
        lambda name: r"C:\Program Files\OWASP ZAP\zap.bat" if name == "zap.bat" else None,
    )
    monkeypatch.setattr(zap.subprocess, "run", fake_run)
    result = zap.baseline("http://127.0.0.1:8080", timeout=5)

    assert captured["args"][0].endswith("zap.bat")
    assert "-cmd" in captured["args"]
    assert result["tool"] == "owasp-zap-baseline"
