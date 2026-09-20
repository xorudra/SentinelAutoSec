import json
import time

from core.db import SessionLocal, init_db
from database.models import Assessment, Target


def test_report_contains_final_assessment_metadata():
    init_db()

    with SessionLocal() as db:
        target = Target(
            name=f"report-metadata-regression-{time.time_ns()}",
            url="http://127.0.0.1:8080",
        )
        db.add(target)
        db.commit()
        db.refresh(target)

        assessment = Assessment(
            target_id=target.id,
            profile="SAFE",
            status="RUNNING",
            current_stage="report_generation",
            progress=95,
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        assessment_id = assessment.id

    from reporting import generator

    path = generator.build_report(
        assessment_id,
        "json",
        status_override="COMPLETED",
        progress_override=100,
    )

    data = json.loads(path.read_text(encoding="utf-8"))

    # Clean up the generated regression-test report.
    path.unlink(missing_ok=True)

    assert data["status"] == "COMPLETED"
    assert data["progress"] == 100
