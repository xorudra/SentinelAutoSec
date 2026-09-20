"""
Finding correlation and deduplication helpers.

This module intentionally operates on structured finding metadata.
It does not execute commands, modify targets, or perform exploitation.
"""


def normalize_fingerprint(value) -> str:
    """Return a canonical fingerprint representation."""
    if value is None:
        return ""

    return " ".join(str(value).strip().lower().split())


def correlate(existing: dict, candidate: dict) -> bool:
    """
    Determine whether two structured findings represent the same issue.

    Correlation is intentionally conservative:
    - both findings must have a non-empty fingerprint
    - fingerprints are normalized before comparison
    """
    existing_fp = normalize_fingerprint(existing.get("fingerprint"))
    candidate_fp = normalize_fingerprint(candidate.get("fingerprint"))

    if not existing_fp or not candidate_fp:
        return False

    return existing_fp == candidate_fp


def finding_key(finding: dict) -> str:
    """Return the canonical key used for finding deduplication."""
    return normalize_fingerprint(finding.get("fingerprint"))
