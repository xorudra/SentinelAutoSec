from datetime import UTC, datetime, timedelta
from uuid import uuid4

from core.db import SessionLocal, init_db
from core.jobs import STALE_JOB_SECONDS, recover_stale_jobs
from database.models import Assessment, Job, Target


def _create_assessment():
    init_db()

    name = f"job-recovery-{uuid4().hex[:8]}"

    with SessionLocal() as db:
        target = Target(
            name=name,
            url="http://127.0.0.1:8080",
            authorization_status=True,
        )

        db.add(target)
        db.flush()

        assessment = Assessment(
            target_id=target.id,
            profile="SAFE",
        )

        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment.id


def test_stale_running_job_is_recovered():
    assessment_id = _create_assessment()

    with SessionLocal() as db:
        job = Job(
            assessment_id=assessment_id,
            status="RUNNING",
            error=None,
        )

        db.add(job)
        db.commit()

        job.updated_at = datetime.now(UTC) - timedelta(seconds=STALE_JOB_SECONDS + 10)

        db.commit()

    recovered = recover_stale_jobs()

    assert assessment_id in recovered

    with SessionLocal() as db:
        job = db.query(Job).filter_by(assessment_id=assessment_id).first()

        assert job is not None
        assert job.status == "QUEUED"
        assert job.error is None


def test_fresh_running_job_is_not_recovered():
    assessment_id = _create_assessment()

    with SessionLocal() as db:
        job = Job(
            assessment_id=assessment_id,
            status="RUNNING",
            error=None,
        )

        db.add(job)
        db.commit()

    recovered = recover_stale_jobs()

    assert assessment_id not in recovered

    with SessionLocal() as db:
        job = db.query(Job).filter_by(assessment_id=assessment_id).first()

        assert job is not None
        assert job.status == "RUNNING"
