"""Tests for the dashboard one-click tool installation endpoints."""

import pytest
from pydantic import ValidationError

from apps.api import main as api_main


@pytest.fixture(autouse=True)
def _reset_install_state():
    initial = {"running": False, "tool": None, "log": [], "error": None, "finished": False}
    api_main._install_state.update(initial)
    yield
    api_main._install_state.update(initial)


def test_install_request_rejects_unknown_tool():
    with pytest.raises(ValidationError):
        api_main.ToolInstallRequest(tool="exploit-kit")


def test_log_capture_splits_lines_and_caps():
    sink: list[str] = []
    capture = api_main._LogCapture(sink)
    capture.write("==> line one\n")
    capture.write("==> partial ")
    capture.write("line two\n\r  progress 50%\n")
    assert sink == ["==> line one", "==> partial line two", "progress 50%"]

    overflow = api_main._LogCapture(sink)
    for i in range(500):
        overflow.write(f"noise {i}\n")
    assert len(sink) <= 300
    assert sink[-1] == "noise 499"


def test_run_tool_install_success(monkeypatch):
    import setup_optional_tools as installer

    def fake_install() -> None:
        print("==> fake download")
        print("==> done")

    monkeypatch.setattr(installer, "install_nuclei", fake_install)
    api_main._run_tool_install("nuclei")

    state = api_main._install_state
    assert state["running"] is False
    assert state["finished"] is True
    assert state["error"] is None
    assert "==> fake download" in state["log"]
    assert "==> done" in state["log"]


def test_run_tool_install_failure_is_captured(monkeypatch):
    import setup_optional_tools as installer

    def fake_install() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(installer, "install_nmap", fake_install)
    api_main._run_tool_install("nmap")

    state = api_main._install_state
    assert state["running"] is False
    assert state["finished"] is True
    assert "boom" in state["error"]


def test_install_endpoint_rejects_concurrent_install():
    api_main._install_state["running"] = True
    with pytest.raises(api_main.HTTPException) as excinfo:
        api_main.install_tool(api_main.ToolInstallRequest(tool="nuclei"))
    assert excinfo.value.status_code == 409
    assert "already in progress" in excinfo.value.detail


def test_install_endpoint_starts_worker_thread(monkeypatch):
    created = {}

    class FakeThread:
        def __init__(self, target, args, daemon):
            created["target"] = target
            created["args"] = args
            created["daemon"] = daemon

        def start(self) -> None:
            created["started"] = True

    monkeypatch.setattr(api_main.threading, "Thread", FakeThread)
    result = api_main.install_tool(api_main.ToolInstallRequest(tool="zap"))

    assert result == {"started": True, "tool": "zap"}
    assert created["started"] is True
    assert created["args"] == ("zap",)
    assert api_main._install_state["running"] is True
    assert api_main._install_state["tool"] == "zap"
    assert api_main._install_state["finished"] is False
    assert api_main._install_state["log"] == []


def test_install_status_reflects_state():
    api_main._install_state.update({"tool": "nuclei", "log": ["a", "b"], "finished": True})
    status = api_main.install_status()
    assert status["running"] is False
    assert status["tool"] == "nuclei"
    assert status["finished"] is True
    assert status["log"] == ["a", "b"]
    # The endpoint returns a copy, not the live list.
    status["log"].append("c")
    assert api_main._install_state["log"] == ["a", "b"]