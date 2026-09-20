import json

from core.db import SessionLocal
from database.models import Checkpoint


def save_checkpoint(
    assessment_id: int, stage: str, completed: list[str], pending: list[str], state: dict
):
    with SessionLocal() as db:
        cp = Checkpoint(
            assessment_id=assessment_id,
            stage=stage,
            completed_modules=json.dumps(completed),
            pending_modules=json.dumps(pending),
            state_json=json.dumps(state, sort_keys=True),
        )
        db.add(cp)
        db.commit()
        db.refresh(cp)
        return cp.id


def latest_checkpoint(assessment_id: int):
    with SessionLocal() as db:
        return (
            db.query(Checkpoint)
            .filter_by(assessment_id=assessment_id)
            .order_by(Checkpoint.id.desc())
            .first()
        )


def checkpoint_state(assessment_id: int) -> dict:
    cp = latest_checkpoint(assessment_id)
    if not cp:
        return {"completed": [], "pending": [], "state": {}}
    return {
        "stage": cp.stage,
        "completed": json.loads(cp.completed_modules),
        "pending": json.loads(cp.pending_modules),
        "state": json.loads(cp.state_json),
    }
