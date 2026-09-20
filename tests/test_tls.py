from modules.tls.analyzer import analyze


def test_tls_skips_http():
    findings, meta = analyze("http://127.0.0.1:8080")
    assert findings == []
    assert meta["checked"] is False


def test_tls_metadata_shape_for_http():
    _, meta = analyze("http://localhost:1")
    assert meta == {"checked": False, "reason": "not_https"}
