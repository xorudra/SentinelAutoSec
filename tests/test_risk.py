from core.risk import calculate_risk


def test_risk_bounds():
    assert 0 <= calculate_risk("HIGH", "HIGH") <= 10


def test_low_confidence_reduces_internal_risk():
    assert calculate_risk("HIGH", "LOW") < calculate_risk("HIGH", "HIGH")
