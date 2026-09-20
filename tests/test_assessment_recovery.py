import uuid

import pytest

from core import orchestrator
from core.checkpoints import (
    checkpoint_state,
    latest_checkpoint,
    save_checkpoint,
)
from core.db import SessionLocal, init_db
from database.models import Assessment, Target, TargetScope


def create_test_assessment():
    """
    Create an authorized target, scope entry, and assessment
    specifically for recovery testing.
    """
    init_db()

    db = SessionLocal()

    target = Target(
        name=f"recovery-test-target-{uuid.uuid4().hex[:8]}",
        url="http://127.0.0.1:8080",
        authorization_status=True,
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    scope = TargetScope(
        target_id=target.id,
        host="127.0.0.1",
        port=8080,
        excluded=False,
    )

    db.add(scope)
    db.commit()

    assessment = Assessment(
        target_id=target.id,
        status="QUEUED",
        profile="SAFE",
    )

    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    assessment_id = assessment.id

    db.close()

    return assessment_id


def get_assessment(assessment_id):
    """Return the current assessment state."""
    db = SessionLocal()

    assessment = db.get(Assessment, assessment_id)

    result = {
        "status": assessment.status,
        "stage": assessment.current_stage,
        "progress": assessment.progress,
        "error": assessment.error,
    }

    db.close()

    return result


def fake_web_analysis(url, timeout):
    """
    Deterministic fake web analyzer.

    This prevents the recovery test from depending on the Docker
    lab or an external HTTP service.
    """
    return [], {
        "url": url,
        "status_code": 200,
        "headers": {},
    }


def test_interrupted_assessment_creates_checkpoint(monkeypatch):
    """
    Start an assessment, intentionally fail the web-security stage,
    and verify that the orchestrator persists a recovery checkpoint.
    """

    assessment_id = create_test_assessment()

    call_count = {"value": 0}

    def fail_once(url, timeout):
        call_count["value"] += 1
        raise RuntimeError("CONTROLLED_TEST_INTERRUPTION")

    monkeypatch.setattr(
        orchestrator,
        "analyze_web",
        fail_once,
    )

    with pytest.raises(
        RuntimeError,
        match="CONTROLLED_TEST_INTERRUPTION",
    ):
        orchestrator.run_assessment(
            assessment_id,
            resume=True,
        )

    assessment = get_assessment(assessment_id)

    assert assessment["status"] == "FAILED"
    assert assessment["stage"] == "web_security"
    assert assessment["error"] == "CONTROLLED_TEST_INTERRUPTION"

    checkpoint = latest_checkpoint(assessment_id)

    assert checkpoint is not None
    assert checkpoint.stage == "web_security"

    checkpoint_data = checkpoint_state(assessment_id)

    assert checkpoint_data["completed"] == ["scope_validation"]

    assert "web_security" in checkpoint_data["pending"]

    assert checkpoint_data["state"]["error"] == "CONTROLLED_TEST_INTERRUPTION"

    assert call_count["value"] == 1


def test_interrupted_assessment_can_resume(monkeypatch):
    """
    Verify the complete recovery flow:

    1. Assessment starts.
    2. Scope validation completes.
    3. Web security intentionally fails.
    4. Failure checkpoint is persisted.
    5. Assessment is resumed.
    6. Web security succeeds.
    7. Remaining stages execute.
    8. Assessment reaches COMPLETED.
    """

    assessment_id = create_test_assessment()

    call_count = {"value": 0}

    def fail_once_then_continue(url, timeout):
        call_count["value"] += 1

        # First execution intentionally fails.
        if call_count["value"] == 1:
            raise RuntimeError("CONTROLLED_TEST_INTERRUPTION")

        # Resume execution uses a deterministic fake analyzer.
        return fake_web_analysis(url, timeout)

    monkeypatch.setattr(
        orchestrator,
        "analyze_web",
        fail_once_then_continue,
    )

    # =========================================================
    # FIRST RUN
    # =========================================================

    with pytest.raises(
        RuntimeError,
        match="CONTROLLED_TEST_INTERRUPTION",
    ):
        orchestrator.run_assessment(
            assessment_id,
            resume=True,
        )

    failed_state = get_assessment(assessment_id)

    assert failed_state["status"] == "FAILED"
    assert failed_state["stage"] == "web_security"

    checkpoint_after_failure = checkpoint_state(assessment_id)

    assert "scope_validation" in (checkpoint_after_failure["completed"])

    assert "web_security" in (checkpoint_after_failure["pending"])

    assert checkpoint_after_failure["state"]["error"] == "CONTROLLED_TEST_INTERRUPTION"

    # =========================================================
    # RESUME
    # =========================================================

    orchestrator.run_assessment(
        assessment_id,
        resume=True,
    )

    completed_state = get_assessment(assessment_id)

    assert completed_state["status"] == "COMPLETED"
    assert completed_state["stage"] == "completed"
    assert completed_state["progress"] == 100
    assert completed_state["error"] is None

    # First call = intentional failure.
    # Second call = successful resume.
    assert call_count["value"] == 2

    # =========================================================
    # FINAL CHECKPOINT
    # =========================================================

    final_checkpoint = latest_checkpoint(assessment_id)

    assert final_checkpoint is not None
    assert final_checkpoint.stage == "completed"

    final_state = checkpoint_state(assessment_id)

    assert final_state["state"]["status"] == "COMPLETED"

    assert final_state["completed"] == [
        "scope_validation",
        "web_security",
        "tls_security",
        "nmap_discovery",
        "extended_web",
        "risk_and_checkpoint",
        "report_generation",
    ]

    assert final_state["pending"] == []


def test_checkpoint_contains_resume_information():
    """
    Verify that a checkpoint contains enough information
    to identify completed and pending stages.
    """

    assessment_id = create_test_assessment()

    save_checkpoint(
        assessment_id=assessment_id,
        stage="web_security",
        completed=[
            "scope_validation",
        ],
        pending=[
            "web_security",
            "tls_security",
            "nmap_discovery",
            "extended_web",
            "risk_and_checkpoint",
            "report_generation",
        ],
        state={
            "status": "INTERRUPTED",
            "reason": "controlled_test_failure",
        },
    )

    checkpoint = latest_checkpoint(assessment_id)

    assert checkpoint is not None
    assert checkpoint.stage == "web_security"

    checkpoint_data = checkpoint_state(assessment_id)

    assert checkpoint_data["completed"] == ["scope_validation"]

    assert "web_security" in (checkpoint_data["pending"])

    assert checkpoint_data["state"]["status"] == "INTERRUPTED"

    assert checkpoint_data["state"]["reason"] == "controlled_test_failure"
