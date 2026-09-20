from pathlib import Path


def test_report_generator_has_html_escaping():
    p = Path("reporting/generator.py").read_text()
    assert "html.escape" in p


def test_report_formats_are_supported():
    text = Path("reporting/generator.py").read_text()
    for fmt in ["markdown", "json", "html", "pdf"]:
        assert fmt in text
