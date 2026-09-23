"""
Lab data visibility: targets flagged is_lab (e.g. "local-lab") are hidden by
default from the dashboard endpoints so a user's own scans stay front and
center until they explicitly switch to include lab data.
"""

from apps.api.main import (
    AssessmentCreate,
    TargetCreate,
    TargetLabUpdate,
    assessments,
    audit_logs,
    create_assessment,
    create_target,
    list_findings,
    list_targets,
    set_target_lab,
)
from core.db import SessionLocal
from database.models import Finding


def _mktarget(name: str, is_lab: bool = False) -> int:
    resp = create_target(
        TargetCreate(name=name, ip="127.0.0.1", authorized=True, is_lab=is_lab)
    )
    return resp["id"]


def _mkfinding(assessment_id: int, title: str) -> None:
    with SessionLocal() as db:
        db.add(
            Finding(
                assessment_id=assessment_id,
                fingerprint=f"fp-{title}",
                title=title,
                severity="LOW",
                confidence="HIGH",
                category="HTTP",
                asset="127.0.0.1",
                evidence="evidence",
                remediation="remediation",
            )
        )
        db.commit()


def test_lab_target_hidden_from_targets_by_default():
    mine = _mktarget("labvis-mine")
    lab = _mktarget("labvis-lab", is_lab=True)

    default = list_targets()
    with_lab = list_targets(include_lab=True)

    ids_default = {t["id"] for t in default}
    ids_lab = {t["id"] for t in with_lab}
    assert mine in ids_default
    assert lab not in ids_default
    assert lab in ids_lab
    assert all(t["is_lab"] is False for t in default if t["id"] == mine)


def test_lab_assessments_and_findings_hidden_by_default():
    mine = _mktarget("labvis-mine2")
    lab = _mktarget("labvis-lab2", is_lab=True)
    a_mine = create_assessment(AssessmentCreate(target_id=mine))["id"]
    a_lab = create_assessment(AssessmentCreate(target_id=lab))["id"]
    _mkfinding(a_mine, "labvis-finding-mine")
    _mkfinding(a_lab, "labvis-finding-lab")

    assert a_mine in {a["id"] for a in assessments()}
    assert a_lab not in {a["id"] for a in assessments()}
    assert a_lab in {a["id"] for a in assessments(include_lab=True)}

    titles = [f["title"] for f in list_findings()]
    assert "labvis-finding-mine" in titles
    assert "labvis-finding-lab" not in titles
    assert "labvis-finding-lab" in [f["title"] for f in list_findings(include_lab=True)]


def test_audit_logs_exclude_lab_targets_by_default():
    _mktarget("labvis-lab3", is_lab=True)
    from database.models import AuditLog

    with SessionLocal() as db:
        db.add(AuditLog(action="SCAN", target="labvis-lab3", result="SUCCESS"))
        db.add(AuditLog(action="SCAN", target="labvis-mine3", result="SUCCESS"))
        db.commit()

    targets_default = {l["target"] for l in audit_logs()}
    assert "labvis-lab3" not in targets_default
    assert "labvis-mine3" in targets_default
    assert "labvis-lab3" in {l["target"] for l in audit_logs(include_lab=True)}


def test_set_target_lab_toggles_visibility():
    t = _mktarget("labvis-toggle")
    resp = set_target_lab(t, TargetLabUpdate(is_lab=True))
    assert resp["is_lab"] is True
    assert t not in {x["id"] for x in list_targets()}
    assert t in {x["id"] for x in list_targets(include_lab=True)}

    set_target_lab(t, TargetLabUpdate(is_lab=False))
    assert t in {x["id"] for x in list_targets()}