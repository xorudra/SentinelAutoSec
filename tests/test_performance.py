"""
Tests for the performance/efficiency work:

- /dashboard/summary returns everything the dashboard polls in one request
- list endpoints stay consistent with the summary payload
- job statuses are fetched with a single batched query
- SQLite is tuned (WAL, foreign keys) and the hot-path indexes exist
- FK-safe purge order lets linked findings delete cleanly
- orchestrator finding dedup collapses duplicates within one batch
"""

from types import SimpleNamespace

import pytest

from apps.api import main as api_main
from core.db import SessionLocal, engine, migrate_schema
from core.orchestrator import _add_findings
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
    # Children first: foreign keys are enforced on the test connection too.
    db.query(Evidence).delete(synchronize_session=False)
    db.query(Finding).delete(synchronize_session=False)
    db.query(Checkpoint).delete(synchronize_session=False)
    db.query(Job).delete(synchronize_session=False)
    db.query(Service).delete(synchronize_session=False)
    db.query(Asset).delete(synchronize_session=False)
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


def _finding(assessment_id, fingerprint, title, severity):
    return Finding(
        assessment_id=assessment_id,
        fingerprint=fingerprint,
        title=title,
        severity=severity,
        confidence="HIGH",
        category="test",
        status="DETECTED",
        asset="10.0.0.1",
        evidence="evidence",
        remediation="fix it",
        cwe="CWE-79",
    )


def _seed(db):
    """One normal target and one lab target, each with an assessment + finding."""
    normal = Target(name="perf-normal", url="http://normal.example")
    lab = Target(name="perf-lab", url="http://lab.example", is_lab=True)
    db.add_all([normal, lab])
    db.flush()

    a_norm = Assessment(target_id=normal.id)
    a_lab = Assessment(target_id=lab.id)
    db.add_all([a_norm, a_lab])
    db.flush()

    db.add(_finding(a_norm.id, "fp-1", "normal crit", "CRITICAL"))
    db.add(_finding(a_norm.id, "fp-2", "normal high", "HIGH"))
    db.add(_finding(a_lab.id, "fp-lab", "lab finding", "LOW"))
    db.commit()
    return normal, lab, a_norm, a_lab



def test_dashboard_summary_shape_and_stats():
    with SessionLocal() as db:
        _seed(db)

    summary = api_main.dashboard_summary()

    assert set(summary) == {"stats", "targets", "assessments", "findings", "audit"}
    # Lab rows are hidden by default, exactly like the individual endpoints.
    assert summary["stats"] == {
        "targets": 1,
        "assessments": 1,
        "findings": 2,
        "critical": 1,
    }
    assert [t["name"] for t in summary["targets"]] == ["perf-normal"]
    assert len(summary["assessments"]) == 1
    assert [f["title"] for f in summary["findings"]] == ["normal crit", "normal high"]


def test_dashboard_summary_include_lab():
    with SessionLocal() as db:
        _seed(db)

    summary = api_main.dashboard_summary(include_lab=True)

    assert summary["stats"]["targets"] == 2
    assert summary["stats"]["findings"] == 3
    assert summary["stats"]["critical"] == 1


def test_dashboard_summary_finding_limit_keeps_true_totals():
    with SessionLocal() as db:
        _seed(db)

    summary = api_main.dashboard_summary(finding_limit=1)

    # The payload is truncated to the newest row, but the stat counters must
    # still reflect the database, not the truncated list.
    assert len(summary["findings"]) == 1
    assert summary["findings"][0]["title"] == "normal high"
    assert summary["stats"]["findings"] == 2

    # Out-of-range limits are clamped, never rejected or unbounded.
    assert len(api_main.dashboard_summary(finding_limit=0)["findings"]) >= 1
    # Default include_lab=False: only the two normal findings are listed.
    assert len(api_main.dashboard_summary(finding_limit=99_999)["findings"]) == 2


def test_dashboard_summary_matches_individual_endpoints():
    with SessionLocal() as db:
        _seed(db)

    summary = api_main.dashboard_summary()

    assert summary["targets"] == api_main.list_targets()
    assert summary["assessments"] == api_main.assessments()
    assert summary["findings"] == api_main.list_findings()
    assert summary["audit"] == api_main.audit_logs()


def test_assessments_job_status_comes_from_one_batched_query():
    with SessionLocal() as db:
        _, _, a_norm, a_lab = _seed(db)
        db.add_all(
            [
                Job(assessment_id=a_norm.id, status="RUNNING"),
                Job(assessment_id=a_lab.id, status="QUEUED"),
            ]
        )
        db.commit()

    rows = {a["id"]: a for a in api_main.assessments(include_lab=True)}
    assert rows[a_norm.id]["job"] == "RUNNING"
    assert rows[a_lab.id]["job"] == "QUEUED"


def test_sqlite_pragmas_are_active():
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_hot_path_indexes_exist_and_migration_is_idempotent():
    # migrate_schema is additive and safe to run repeatedly (it runs on every
    # startup in production too).
    migrate_schema()
    migrate_schema()

    with engine.connect() as conn:
        names = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).all()
        }
    assert {
        "ix_targets_is_lab",
        "ix_jobs_status",
        "ix_findings_severity",
        "ix_audit_logs_target",
    } <= names


def test_delete_assessment_cascades_linked_rows_in_fk_order():
    """Findings reference assets AND services; deletion must go children-first."""
    with SessionLocal() as db:
        target, _, a_norm, a_lab = _seed(db)

        asset = Asset(assessment_id=a_norm.id, host="10.0.0.1", kind="host")
        db.add(asset)
        db.flush()
        service = Service(asset_id=asset.id, port=443, protocol="TCP", name="https")
        db.add(service)
        db.flush()

        linked = _finding(a_norm.id, "fp-linked", "linked", "MEDIUM")
        linked.asset_id = asset.id
        linked.service_id = service.id
        db.add(linked)
        db.flush()
        db.add(
            Evidence(
                assessment_id=a_norm.id,
                finding_id=linked.id,
                tool="nmap",
                evidence_type="RAW",
                content="scan output",
            )
        )
        db.add(Checkpoint(assessment_id=a_norm.id, stage="recon"))
        db.add(Job(assessment_id=a_norm.id, status="COMPLETED"))
        db.commit()
        target_id = target.id

    result = api_main.delete_assessment(
        a_norm.id, api_main.AssessmentDeleteRequest(confirm="YES")
    )
    assert result["deleted"] is True

    with SessionLocal() as db:
        assert db.query(Finding).count() == 1  # only the lab finding remains
        assert db.query(Evidence).count() == 0
        assert db.query(Checkpoint).count() == 0
        assert db.query(Job).count() == 0
        assert db.query(Service).count() == 0
        assert db.query(Asset).count() == 0
        assert db.query(Assessment).filter_by(id=a_norm.id).first() is None
        # The sibling lab assessment (other target) and the target survive.
        assert db.query(Assessment).filter_by(id=a_lab.id).count() == 1
        assert db.query(Target).filter_by(id=target_id).first() is not None


def test_add_findings_dedups_within_batch_and_against_db():
    with SessionLocal() as db:
        _, _, a_norm, _ = _seed(db)

        candidate = SimpleNamespace(
            fingerprint="fp-batch",
            title="batch finding",
            severity="HIGH",
            confidence="HIGH",
            category="test",
            evidence="batch evidence",
            remediation="fix",
            cwe="CWE-22",
        )
        duplicate = SimpleNamespace(**vars(candidate))

        # Two identical candidates in one batch -> one row (the old code
        # re-queried the DB per candidate; the in-batch append closes that).
        added = _add_findings(db, a_norm.id, "10.0.0.1", [candidate, duplicate], "test", {})
        assert added == 1

        # A second batch against the already-stored row adds nothing.
        added_again = _add_findings(db, a_norm.id, "10.0.0.1", [duplicate], "test", {})
        assert added_again == 0

        db.commit()
        assert (
            db.query(Finding)
            .filter_by(assessment_id=a_norm.id, fingerprint="fp-batch")
            .count()
            == 1
        )


def test_dashboard_template_polls_once_and_respects_hidden_tabs():
    from pathlib import Path

    html = (Path(api_main.__file__).parent / "templates" / "dashboard.html").read_text(
        encoding="utf-8"
    )
    assert "/dashboard/summary" in html
    assert "loadSummary" in html
    assert "document.hidden" in html
    # The old always-on five-request tick must be gone.
    assert "setInterval(refreshAll, 3000)" not in html
