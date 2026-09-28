"""Tests for the tool locator: PATH first, then common install locations."""

import pytest

from integrations.external import locate as locate_module
from integrations.external.locate import locate


@pytest.fixture(autouse=True)
def _fresh_locator_cache():
    locate_module.clear_cache()
    yield
    locate_module.clear_cache()


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


def test_locate_memoizes_repeated_lookups(monkeypatch):
    calls = []
    monkeypatch.setattr(locate_module, "_FALLBACK_DIRS", ())

    def fake_which(name):
        calls.append(name)
        return f"/usr/bin/{name}"

    monkeypatch.setattr(locate_module, "which", fake_which)
    assert locate("nmap") == "/usr/bin/nmap"
    assert locate("nmap") == "/usr/bin/nmap"
    assert calls == ["nmap"]  # second lookup served from the cache


def test_locate_cache_entries_expire(monkeypatch):
    calls = []
    monkeypatch.setattr(locate_module, "_FALLBACK_DIRS", ())
    monkeypatch.setattr(locate_module, "which", lambda name: calls.append(name) or f"/usr/bin/{name}")
    monkeypatch.setattr(locate_module, "_CACHE_TTL_SECONDS", -1.0)  # never fresh
    assert locate("nuclei") == "/usr/bin/nuclei"
    assert locate("nuclei") == "/usr/bin/nuclei"
    assert len(calls) == 2  # expired entries are re-resolved


def test_clear_cache_forces_fresh_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr(locate_module, "_FALLBACK_DIRS", ())
    monkeypatch.setattr(locate_module, "which", lambda name: calls.append(name) or f"/usr/bin/{name}")
    assert locate("zap.bat") == "/usr/bin/zap.bat"
    assert len(calls) == 1
    locate_module.clear_cache()
    assert locate("zap.bat") == "/usr/bin/zap.bat"
    assert len(calls) == 2