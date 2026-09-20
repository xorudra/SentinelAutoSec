from pathlib import Path


def test_api_module_contains_core_routes():
    text = Path("apps/api/main.py").read_text()
    for route in [
        "/health",
        "/targets",
        "/assessments",
        "/findings",
        "/evidence",
        "/assets",
        "/audit-logs",
        "/reports",
    ]:
        assert route in text
