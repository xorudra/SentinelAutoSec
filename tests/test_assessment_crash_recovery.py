import time
from datetime import UTC, datetime, timedelta

from core import jobs
from core.checkpoints import checkpoint_state, save_checkpoint
from core.db import SessionLocal, init_db
from database.models import Assessment, Job, Target


def _make_recovery_assessment():
    unique = f"recovery-{time.time_ns()}"

    init_db()

    with SessionLocal() as db:
        target = Target(
            name=unique,
            url="http://127.0.0.1:8080",
        )
        db.add(target)
        db.commit()
        db.refresh(target)

        assessment = Assessment(
            target_id=target.id,
            profile="SAFE",
            status="QUEUED",
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment.id


def test_realistic_crash_restart_recovery(monkeypatch):
    assessment_id = _make_recovery_assessment()

    completed = [
        "scope_validation",
        "web_security",
    ]

    pending = [
        "tls_security",
        "nmap_discovery",
        "extended_web",
        "risk_and_checkpoint",
        "report_generation",
    ]

    save_checkpoint(
        assessment_id=assessment_id,
        stage="web_security",
        completed=completed,
        pending=pending,
        state={
            "status": "RUNNING",
            "simulated_crash": True,
            "message": "Worker process interrupted after web_security.",
        },
    )

    with SessionLocal() as db:
        job = Job(
            assessment_id=assessment_id,
            status="RUNNING",
            error=None,
            updated_at=datetime.now(UTC) - timedelta(seconds=jobs.STALE_JOB_SECONDS + 10),
        )
        db.add(job)
        db.commit()

    recovered = jobs.recover_stale_jobs()

    assert assessment_id in recovered

    with SessionLocal() as db:
        job = db.query(Job).filter_by(assessment_id=assessment_id).first()

        assert job is not None
        assert job.status == "QUEUED"
        assert job.error is None

    calls = []

    def fake_run_assessment(recovered_assessment_id, resume=True):
        calls.append(
            {
                "assessment_id": recovered_assessment_id,
                "resume": resume,
            }
        )

        state = checkpoint_state(recovered_assessment_id)

        assert state["state"]["status"] == "RUNNING"
        assert state["state"]["simulated_crash"] is True

    monkeypatch.setattr(
        jobs,
        "run_assessment",
        fake_run_assessment,
    )

    jobs.submit_assessment(assessment_id)

    deadline = time.time() + 5

    while time.time() < deadline:
        with SessionLocal() as db:
            job = db.query(Job).filter_by(assessment_id=assessment_id).first()

            if job and job.status == "COMPLETED":
                break

        time.sleep(0.05)

    with SessionLocal() as db:
        job = db.query(Job).filter_by(assessment_id=assessment_id).first()

        assert job is not None, "Recovery job disappeared from the database"
        assert job.status == "COMPLETED", (
            f"Recovery worker did not complete. status={job.status!r}, error={job.error!r}"
        )

    assert len(calls) == 1
    assert calls[0]["assessment_id"] == assessment_id
    assert calls[0]["resume"] is True
