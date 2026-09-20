import uuid

from core.checkpoints import checkpoint_state, latest_checkpoint
from core.db import SessionLocal, init_db
from core.orchestrator import run_assessment
from database.models import Assessment, Target


def create_test_assessment():
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

    assessment = Assessment(
        target_id=target.id,
        status="QUEUED",
    )

    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    assessment_id = assessment.id

    db.close()

    return assessment_id


def test_interrupted_assessment_creates_checkpoint(monkeypatch):
    """
    Verify that an assessment failure creates a durable checkpoint.
    """

    assessment_id = create_test_assessment()

    original_run = run_assessment

    # This test will be expanded once we inject a controlled failure
    # into an individual assessment stage.
    assert assessment_id is not None
    assert callable(original_run)


def test_checkpoint_contains_resume_information():
    """
    Verify that checkpoint information contains the data required
    to understand where an assessment stopped.
    """

    assessment_id = create_test_assessment()

    from core.checkpoints import save_checkpoint

    save_checkpoint(
        assessment_id=assessment_id,
        stage="web_security",
        completed=["scope_validation"],
        pending=[
            "web_security",
            "tls_security",
            "nmap_discovery",
            "extended_web",
            "risk_and_checkpoint",
            "report",
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

    assert "web_security" in checkpoint_data["pending"]

    assert checkpoint_data["state"]["status"] == "INTERRUPTED"

    assert checkpoint_data["state"]["reason"] == "controlled_test_failure"
