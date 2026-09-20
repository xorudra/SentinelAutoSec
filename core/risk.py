SEVERITY_BASE = {"INFO": 1, "LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
CONFIDENCE_MULTIPLIER = {"LOW": 0.6, "MEDIUM": 0.8, "HIGH": 1.0}


def calculate_risk(
    severity: str, confidence: str, asset_criticality: float = 1.0, exposure: float = 1.0
) -> float:
    severity = severity.upper()
    confidence = confidence.upper()
    if severity not in SEVERITY_BASE or confidence not in CONFIDENCE_MULTIPLIER:
        raise ValueError("Unsupported severity or confidence.")
    raw = SEVERITY_BASE[severity] * CONFIDENCE_MULTIPLIER[confidence] * asset_criticality * exposure
    return round(min(10.0, raw), 2)
