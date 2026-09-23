"""Tests for the tool locator: PATH first, then common install locations."""

from integrations.external import locate as locate_module
from integrations.external.locate import locate


def test_locate_prefers_path(monkeypatch):
    monkeypatch.setattr(locate_module, "which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    assert locate("nmap") == "/usr/bin/nmap"


def test_locate_falls_back_to_extra_dirs(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "nuclei.exe").write_bytes(b"binary")
    monkeypatch.setattr(locate_module, "which", lambda name: None)
    monkeypatch.setattr(locate_module, "_FALLBACK_DIRS", (fake_bin,))
    assert locate("nuclei") == str(fake_bin / "nuclei.exe")


def test_locate_tries_windows_executable_suffixes(monkeypatch, tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "zap.bat").write_bytes(b"x")
    (fake_bin / "nuclei.exe").write_bytes(b"x")
    monkeypatch.setattr(locate_module, "which", lambda name: None)
    monkeypatch.setattr(locate_module, "_FALLBACK_DIRS", (fake_bin,))
    assert locate("zap.bat") == str(fake_bin / "zap.bat")
    assert locate("nuclei") == str(fake_bin / "nuclei.exe")


def test_locate_returns_none_when_missing(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(locate_module, "which", lambda name: None)
    monkeypatch.setattr(locate_module, "_FALLBACK_DIRS", (empty,))
    assert locate("nuclei") is None


def test_project_tools_bin_is_in_fallbacks():
    normalized = [str(d).replace("\\", "/").lower() for d in locate_module._FALLBACK_DIRS]
    assert any(path.endswith("tools/bin") for path in normalized)