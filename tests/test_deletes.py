"""Tests for the target/assessment deletion endpoints behind the dashboard Delete buttons."""

import pytest
from pydantic import ValidationError

from apps.api import main as api_main
from core.db import SessionLocal
from database.models import (
    Assessment,
    Asset,
    AuditLog,
    Checkpoint,
    Evidence,
    Finding,
    Job,
    Service,
    Target,
    TargetScope,
)


def _cleanup(db):
    db.query(Evidence).delete(synchronize_session=False)
    db.query(Service).delete(synchronize_session=False)
    db.query(Asset).delete(synchronize_session=False)
    db.query(Finding).delete(synchronize_session=False)
    db.query(Checkpoint).delete(synchronize_session=False)
    db.query(Job).delete(synchronize_session=False)
    db.query(Assessment).delete(synchronize_session=False)
    db.query(TargetScope).delete(synchronize_session=False)
    db.query(Target).delete(synchronize_session=False)
    db.query(AuditLog).delete(synchronize_session=False)
    db.commit()


@pytest.fixture(autouse=True)
def _isolated_tables():
    with SessionLocal() as db:
        _cleanup(db)
    yield
    with SessionLocal() as db:
        _cleanup(db)


def _target(db, name):
    t = Target(name=name, url="http://127.0.0.1:8080", is_lab=True)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _assessment(db, target_id):
    a = Assessment(target_id=target_id)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _finding(db, assessment_id):
    f = Finding(
        assessment_id=assessment_id,
        fingerprint="fp-1",
        title="Test finding",
        severity="HIGH",
        confidence="HIGH",
        category="web",
        asset="127.0.0.1",
        evidence="raw evidence",
        remediation="fix it",
    )
    db.add(f)
    db.commit()
    return f


def test_delete_requests_require_the_word_yes():
    with pytest.raises(ValidationError):
        api_main.TargetDeleteRequest(confirm="delete")
    with pytest.raises(ValidationError):
        api_main.AssessmentDeleteRequest(confirm="")
    assert api_main.TargetDeleteRequest(confirm="YES").confirm == "YES"
    assert api_main.AssessmentDeleteRequest(confirm="yes").confirm == "yes"


def test_delete_target_rejects_missing_confirmation():
    with SessionLocal() as db:
        t = _target(db, "no-confirm-target")
        tid = t.id
    # "yes" passes the model pattern but not the strict endpoint check.
    with pytest.raises(api_main.HTTPException) as excinfo:
        api_main.delete_target(tid, api_main.TargetDeleteRequest(confirm="yes"))
    assert excinfo.value.status_code == 400
    with SessionLocal() as db:
        assert db.get(Target, tid) is not None


def test_delete_target_returns_404_for_unknown_id():
    with pytest.raises(api_main.HTTPException) as excinfo:
        api_main.delete_target(999999, api_main.TargetDeleteRequest(confirm="YES"))
    assert excinfo.value.status_code == 404


def test_delete_target_cascades_all_dependent_rows():
    with SessionLocal() as db:
        t = _target(db, "cascade-target")
        db.add(TargetScope(target_id=t.id, host="127.0.0.1", port=8080))
        a1 = _assessment(db, t.id)
        _assessment(db, t.id)
        asset = Asset(assessment_id=a1.id, host="127.0.0.1")
        db.add(asset)
        db.commit()
        db.refresh(asset)
        db.add(Service(asset_id=asset.id, port=8080, name="http"))
        _finding(db, a1.id)
        db.add(Evidence(assessment_id=a1.id, tool="nmap", evidence_type="RAW", content="c"))
        db.add(Checkpoint(assessment_id=a1.id, stage="DISCOVERY"))
        db.add(Job(assessment_id=a1.id, status="COMPLETED"))
        db.commit()
        tid = t.id

    result = api_main.delete_target(tid, api_main.TargetDeleteRequest(confirm="YES"))

    assert result == {"deleted": True, "id": tid, "name": "cascade-target"}
    with SessionLocal() as db:
        assert db.get(Target, tid) is None
        assert db.query(Assessment).count() == 0
        assert db.query(TargetScope).count() == 0
        assert db.query(Asset).count() == 0
        assert db.query(Service).count() == 0
        assert db.query(Finding).count() == 0
        assert db.query(Evidence).count() == 0
        assert db.query(Checkpoint).count() == 0
        assert db.query(Job).count() == 0
        log = db.query(AuditLog).filter_by(action="TARGET_DELETE").first()
        assert log is not None
        assert log.target == "cascade-target"


def test_delete_target_refused_while_job_active(monkeypatch):
    with SessionLocal() as db:
        t = _target(db, "busy-target")
        _assessment(db, t.id)
        tid = t.id
    monkeypatch.setattr(api_main, "job_status", lambda _aid: "RUNNING")
    with pytest.raises(api_main.HTTPException) as excinfo:
        api_main.delete_target(tid, api_main.TargetDeleteRequest(confirm="YES"))
    assert excinfo.value.status_code == 409
    assert "queued or running" in excinfo.value.detail
    with SessionLocal() as db:
        assert db.get(Target, tid) is not None


def test_delete_assessment_cascades_and_keeps_target():
    with SessionLocal() as db:
        t = _target(db, "assessment-delete-target")
        a = _assessment(db, t.id)
        _finding(db, a.id)
        db.add(Evidence(assessment_id=a.id, tool="zap", evidence_type="RAW", content="c"))
        db.add(Checkpoint(assessment_id=a.id, stage="EXPLOIT"))
        db.commit()
        aid, tid = a.id, t.id

    result = api_main.delete_assessment(aid, api_main.AssessmentDeleteRequest(confirm="YES"))

    assert result == {"deleted": True, "id": aid}
    with SessionLocal() as db:
        assert db.get(Assessment, aid) is None
        assert db.query(Finding).count() == 0
        assert db.query(Evidence).count() == 0
        assert db.query(Checkpoint).count() == 0
        assert db.get(Target, tid) is not None
        log = db.query(AuditLog).filter_by(action="ASSESSMENT_DELETE").first()
        assert log is not None
        assert log.target == "assessment-delete-target"


def test_delete_assessment_refused_while_queued(monkeypatch):
    with SessionLocal() as db:
        t = _target(db, "queued-assessment-target")
        a = _assessment(db, t.id)
        aid = a.id
    monkeypatch.setattr(api_main, "job_status", lambda _x: "QUEUED")
    with pytest.raises(api_main.HTTPException) as excinfo:
        api_main.delete_assessment(aid, api_main.AssessmentDeleteRequest(confirm="YES"))
    assert excinfo.value.status_code == 409
    with SessionLocal() as db:
        assert db.get(Assessment, aid) is not None


def test_delete_assessment_returns_404_for_unknown_id():
    with pytest.raises(api_main.HTTPException) as excinfo:
        api_main.delete_assessment(424242, api_main.AssessmentDeleteRequest(confirm="YES"))
    assert excinfo.value.status_code == 404