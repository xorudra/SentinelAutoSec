from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread

from core.config import settings
from core.db import SessionLocal
from core.orchestrator import run_assessment
from database.models import AuditLog, Job

STALE_JOB_SECONDS = settings.job_stale_seconds


_executor = ThreadPoolExecutor(
    max_workers=2,
    thread_name_prefix="sentinelsec",
)

_lock = Lock()


def _now():
    return datetime.now(UTC)


def _job_is_stale(job: Job) -> bool:
    if job.status != "RUNNING":
        return False

    if not job.updated_at:
        return True

    updated = job.updated_at

    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=UTC)

    age = _now() - updated

    return age > timedelta(seconds=settings.job_stale_seconds)


def _heartbeat(
    assessment_id: int,
    stop_event: Event,
) -> None:
    """
    Periodically update the Job heartbeat while the worker is alive.

    The heartbeat uses the existing Job.updated_at column, so no
    database migration is required.
    """

    interval = max(
        0.1,
        settings.job_heartbeat_seconds,
    )

    while not stop_event.wait(interval):
        try:
            with _lock, SessionLocal() as db:
                job = db.query(Job).filter_by(assessment_id=assessment_id).first()

                if not job or job.status != "RUNNING":
                    return

                job.updated_at = _now()
                db.commit()

        except (OSError, RuntimeError):
            # Heartbeat failure must never crash the assessment worker.
            # The main worker remains responsible for the assessment.
            continue


def recover_stale_jobs() -> list[int]:
    """
    Convert stale RUNNING jobs back to QUEUED.

    Startup can then submit these jobs again and the orchestrator
    will resume from the latest durable checkpoint.
    """

    recovered = []

    with _lock, SessionLocal() as db:
        jobs = db.query(Job).filter(Job.status == "RUNNING").all()

        for job in jobs:
            if not _job_is_stale(job):
                continue

            job.status = "QUEUED"
            job.error = None
            job.updated_at = _now()

            db.add(
                AuditLog(
                    action="JOB_RECOVERED",
                    target=str(job.assessment_id),
                    result="RECOVERED",
                    details=("Stale RUNNING job reset to QUEUED for checkpoint-based recovery."),
                )
            )

            recovered.append(job.assessment_id)

        db.commit()

    return recovered


def submit_assessment(assessment_id: int) -> None:
    """
    Queue an assessment.

    Active RUNNING jobs are not duplicated.
    Stale RUNNING jobs can be recovered.
    """

    with SessionLocal() as db:
        job = db.query(Job).filter_by(assessment_id=assessment_id).first()

        if job and job.status == "RUNNING":
            if not _job_is_stale(job):
                return

            job.status = "QUEUED"
            job.error = None

        elif job and job.status == "QUEUED":
            # A QUEUED job must be submitted to the worker.
            # This is important for startup recovery after a stale
            # RUNNING job has been reset to QUEUED.
            job.error = None

        elif not job:
            job = Job(
                assessment_id=assessment_id,
                status="QUEUED",
            )
            db.add(job)

        else:
            job.status = "QUEUED"
            job.error = None

        job.updated_at = _now()

        db.commit()

    def worker() -> None:
        stop_event = Event()

        with _lock, SessionLocal() as db:
            job = db.query(Job).filter_by(assessment_id=assessment_id).first()

            if job:
                job.status = "RUNNING"
                job.error = None
                job.updated_at = _now()

                db.add(
                    AuditLog(
                        action="JOB_STARTED",
                        target=str(assessment_id),
                        result="RUNNING",
                        details=("Assessment worker started with checkpoint resume enabled."),
                    )
                )

                db.commit()

        heartbeat_thread = Thread(
            target=_heartbeat,
            args=(assessment_id, stop_event),
            name=f"sentinelsec-heartbeat-{assessment_id}",
            daemon=True,
        )

        heartbeat_thread.start()

        try:
            run_assessment(
                assessment_id,
                resume=True,
            )

            status = "COMPLETED"
            error = None

        except (OSError, RuntimeError, ValueError) as exc:
            status = "FAILED"
            error = str(exc)

        finally:
            stop_event.set()
            heartbeat_thread.join(
                timeout=max(
                    1.0,
                    settings.job_heartbeat_seconds + 1,
                )
            )

        with _lock, SessionLocal() as db:
            job = db.query(Job).filter_by(assessment_id=assessment_id).first()

            if job:
                job.status = status
                job.error = error
                job.updated_at = _now()

                db.add(
                    AuditLog(
                        action=("JOB_COMPLETED" if status == "COMPLETED" else "JOB_FAILED"),
                        target=str(assessment_id),
                        result=status,
                        details=error,
                    )
                )

                db.commit()

    _executor.submit(worker)


def job_status(assessment_id: int) -> str | None:
    with SessionLocal() as db:
        job = db.query(Job).filter_by(assessment_id=assessment_id).first()

        return job.status if job else None
