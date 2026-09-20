import uuid

from core.checkpoints import (
    checkpoint_state,
    latest_checkpoint,
    save_checkpoint,
)
from core.db import SessionLocal, init_db
from database.models import Assessment, Target


def create_test_assessment():
    init_db()

    db = SessionLocal()

    target = Target(
        name=f"checkpoint-test-target-{uuid.uuid4().hex[:8]}",
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

    aid = assessment.id

    db.close()

    return aid


def test_checkpoint_save_and_load():
    assessment_id = create_test_assessment()

    save_checkpoint(
        assessment_id=assessment_id,
        stage="web_security",
        completed=["scope_validation"],
        pending=["web_security"],
        state={
            "status": "RUNNING",
            "current_target": "http://127.0.0.1:8080",
        },
    )

    cp = latest_checkpoint(assessment_id)

    assert cp is not None
    assert cp.stage == "web_security"

    state = checkpoint_state(assessment_id)

    assert state["state"]["status"] == "RUNNING"
    assert state["state"]["current_target"] == "http://127.0.0.1:8080"


def test_latest_checkpoint_wins():
    assessment_id = create_test_assessment()

    save_checkpoint(
        assessment_id=assessment_id,
        stage="scope_validation",
        completed=[],
        pending=["web_security"],
        state={"step": 1},
    )

    save_checkpoint(
        assessment_id=assessment_id,
        stage="web_security",
        completed=["scope_validation"],
        pending=[],
        state={"step": 2},
    )

    cp = latest_checkpoint(assessment_id)

    assert cp is not None
    assert cp.stage == "web_security"

    state = checkpoint_state(assessment_id)

    assert state["state"]["step"] == 2


def test_checkpoint_state_preserves_nested_json():
    assessment_id = create_test_assessment()

    nested = {
        "status": "RUNNING",
        "assets": [
            {
                "host": "127.0.0.1",
                "port": 8080,
                "services": ["http"],
            }
        ],
        "metadata": {
            "profile": "SAFE",
        },
    }

    save_checkpoint(
        assessment_id=assessment_id,
        stage="risk_and_checkpoint",
        completed=["scope_validation"],
        pending=["report"],
        state=nested,
    )

    state = checkpoint_state(assessment_id)

    assert state["state"] == nested
    assert state["state"]["assets"][0]["port"] == 8080
    assert state["state"]["metadata"]["profile"] == "SAFE"


def test_missing_checkpoint_returns_clean_state():
    assessment_id = create_test_assessment()

    state = checkpoint_state(assessment_id)

    assert state == {
        "completed": [],
        "pending": [],
        "state": {},
    }
