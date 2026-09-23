
import pytest

from integrations.nmap import adapter


def _xml(ports):
    entries = "".join(
        f"<port protocol='tcp' portid='{p}'><state state='open'/>"
        f"<service name='http' version='1.0'/></port>"
        for p in ports
    )
    return f"<nmaprun><host><ports>{entries}</ports></host></nmaprun>"


class _FakeProc:
    returncode = 0
    stderr = ""

    def __init__(self, stdout):
        self.stdout = stdout


def test_scan_with_explicit_ports_single_pass(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeProc(_xml([80, 443]))

    monkeypatch.setattr(adapter, "available", lambda: True)
    monkeypatch.setattr(adapter.subprocess, "run", fake_run)

    results = adapter.scan("127.0.0.1", [443, 80, 80], timeout=60)

    assert len(calls) == 1
    assert "-p" in calls[0] and calls[0][calls[0].index("-p") + 1] == "80,443"
    assert calls[0][0] == "nmap"
    assert [r["port"] for r in results] == [80, 443]
    assert results[0]["name"] == "http"


def test_scan_without_ports_is_two_phase_all_ports(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "-p-" in cmd:
            return _FakeProc(_xml([8080, 22]))
        return _FakeProc(_xml([22, 8080]))

    monkeypatch.setattr(adapter, "available", lambda: True)
    monkeypatch.setattr(adapter.subprocess, "run", fake_run)

    results = adapter.scan("127.0.0.1", None)

    assert len(calls) == 2
    assert "-p-" in calls[0] and "-T4" in calls[0]
    assert calls[1][calls[1].index("-p") + 1] == "22,8080"
    assert [r["port"] for r in results] == [22, 8080]


def test_scan_without_ports_and_no_open_ports(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeProc(_xml([]))

    monkeypatch.setattr(adapter, "available", lambda: True)
    monkeypatch.setattr(adapter.subprocess, "run", fake_run)

    assert adapter.scan("127.0.0.1", None) == []
    assert len(calls) == 1


def test_scan_unavailable_raises(monkeypatch):
    monkeypatch.setattr(adapter, "available", lambda: False)
    with pytest.raises(adapter.NmapUnavailable):
        adapter.scan("127.0.0.1", [80])


def test_parse_xml_ignores_closed_ports():
    xml = (
        "<nmaprun><host><ports>"
        "<port protocol='tcp' portid='80'><state state='open'/></port>"
        "<port protocol='tcp' portid='81'><state state='closed'/></port>"
        "</ports></host></nmaprun>"
    )
    assert [r["port"] for r in adapter._parse_xml(xml)] == [80]


def test_port_arg_joins_ports():
    assert adapter._port_arg([80, 443]) == "80,443"

