"""
Contract tests for the dashboard template (UI <-> inline JavaScript).

The dashboard is a single HTML file whose inline script addresses DOM nodes by
id and wires rows with inline onclick/onchange handlers. A restyle that drops
or renames an id silently breaks features at runtime (nothing else type-checks
HTML), so the wiring is pinned here:

- every element id the script reads must exist in the markup
- every handler referenced from markup must be defined in the script
- ids must stay unique (getElementById returns the first match)
- the performance contract from test_performance.py keeps applying
"""

import re
from pathlib import Path

from apps.api import main as api_main

TEMPLATE = Path(api_main.__file__).parent / "templates" / "dashboard.html"

# Ids the inline script dereferences via $() / getElementById().
REQUIRED_IDS = {
    "assess",
    "audit",
    "detail",
    "f-filter",
    "findings",
    "install-panel",
    "lab-toggle",
    "sc-excl",
    "sc-host",
    "sc-port",
    "sc-target",
    "sc-msg",
    "s-assess",
    "s-critical",
    "s-findings",
    "s-targets",
    "t-auth",
    "t-ip",
    "t-lab",
    "t-msg",
    "t-name",
    "t-url",
    "targets",
    "tools",
    "updated",
    "a-msg",
    "a-profile",
    "a-target",
    "sev-bar",
    "sev-legend",
    "n-assess",
    "n-findings",
    "n-targets",
}


def _template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def _script(html: str) -> str:
    blocks = re.findall(r"(?s)<script>(.*?)</script>", html)
    assert blocks, "dashboard template has no inline <script> block"
    return blocks[-1]


def test_dashboard_exposes_every_id_the_script_reads():
    html = _template()
    ids = set(re.findall(r'id="([^"]+)"', html))
    missing = sorted(REQUIRED_IDS - ids)
    assert not missing, f"script references ids missing from markup: {missing}"


def test_dashboard_ids_are_unique():
    html = _template()
    ids = re.findall(r'id="([^"]+)"', html)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, (
        "duplicate ids: getElementById would silently return the first match "
        f"and break the others: {dupes}"
    )


def test_dashboard_inline_handlers_are_defined():
    html = _template()
    script = _script(html)
    handlers = set(re.findall(r'on(?:click|change)="([A-Za-z_]+)\(', html))
    assert handlers, "expected inline handlers in the markup"
    undefined = sorted(
        h for h in handlers if not re.search(rf"function\s+{re.escape(h)}\b", script)
    )
    assert not undefined, f"handlers referenced in markup but not defined: {undefined}"


def test_dashboard_keeps_summary_polling_contract():
    html = _template()
    assert "/dashboard/summary" in html
    assert "loadSummary" in html
    assert "document.hidden" in html
    assert "setInterval(refreshAll, 3000)" not in html
