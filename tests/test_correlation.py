from core.correlation import correlate, finding_key, normalize_fingerprint


def test_same_fingerprint_correlates():
    assert correlate({"fingerprint": "x"}, {"fingerprint": "x"})


def test_fingerprint_normalization_correlates():
    assert correlate(
        {"fingerprint": "  Missing-CSP  "},
        {"fingerprint": "missing-csp"},
    )


def test_fingerprint_case_difference_correlates():
    assert correlate(
        {"fingerprint": "COOKIE-SECURE"},
        {"fingerprint": "cookie-secure"},
    )


def test_different_fingerprint_does_not_correlate():
    assert not correlate(
        {"fingerprint": "missing-csp"},
        {"fingerprint": "missing-hsts"},
    )


def test_missing_fingerprint_does_not_correlate():
    assert not correlate(
        {"fingerprint": ""},
        {"fingerprint": "missing-csp"},
    )


def test_none_fingerprint_does_not_correlate():
    assert not correlate(
        {"fingerprint": None},
        {"fingerprint": None},
    )


def test_finding_key_is_canonical():
    assert finding_key({"fingerprint": "  TEST-FINDING  "}) == "test-finding"


def test_normalize_fingerprint_collapses_whitespace():
    assert normalize_fingerprint("  hello    world  ") == "hello world"
