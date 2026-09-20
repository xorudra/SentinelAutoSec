import json
import time
from pathlib import Path

import pytest

from core import orchestrator
from core.checkpoints import checkpoint_state
from core.db import SessionLocal, init_db
from database.models import Assessment, Target, TargetScope


def _make_assessment():
    init_db()

    unique = f"report-stage-{time.time_ns()}"

    with SessionLocal() as db:
        target = Target(
            name=unique,
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

        assessment = Assessment(
            target_id=target.id,
            profile="SAFE",
            status="QUEUED",
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment.id


def _fake_web(url, timeout):
    return [], {
        "url": url,
        "status_code": 200,
        "headers": {},
    }


def test_report_generation_is_real_orchestrator_stage(monkeypatch, tmp_path):
    assessment_id = _make_assessment()

    monkeypatch.setattr(
        orchestrator,
        "analyze_web",
        _fake_web,
    )

    generated = []

    def fake_build_report(aid, fmt="markdown"):
        assert aid == assessment_id
        generated.append(fmt)

        path = tmp_path / f"assessment-{aid}.{fmt}"
        path.write_text(
            json.dumps(
                {
                    "assessment": aid,
                    "format": fmt,
                }
            ),
            encoding="utf-8",
        )
        return path

    monkeypatch.setattr(
        orchestrator,
        "build_report",
        fake_build_report,
    )

    orchestrator.run_assessment(
        assessment_id,
        resume=True,
    )

    with SessionLocal() as db:
        assessment = db.get(Assessment, assessment_id)

        assert assessment.status == "COMPLETED"
        assert assessment.current_stage == "completed"
        assert assessment.progress == 100

    assert generated == [
        "markdown",
        "json",
        "html",
        "pdf",
    ]

    state = checkpoint_state(assessment_id)

    assert "report_generation" in state["completed"]
    assert state["pending"] == []
    assert state["state"]["status"] == "COMPLETED"
    assert set(state["state"]["reports"]) == {
        "markdown",
        "json",
        "html",
        "pdf",
    }


def test_report_failure_leaves_assessment_failed(monkeypatch):
    assessment_id = _make_assessment()

    monkeypatch.setattr(
        orchestrator,
        "analyze_web",
        _fake_web,
    )

    calls = []

    def failing_report(aid, fmt="markdown"):
        calls.append(fmt)

        if fmt == "html":
            raise RuntimeError("CONTROLLED_REPORT_FAILURE")

        return Path(f"assessment-{aid}-{fmt}.tmp")

    monkeypatch.setattr(
        orchestrator,
        "build_report",
        failing_report,
    )

    with pytest.raises(
        RuntimeError,
        match="CONTROLLED_REPORT_FAILURE",
    ):
        orchestrator.run_assessment(
            assessment_id,
            resume=True,
        )

    with SessionLocal() as db:
        assessment = db.get(Assessment, assessment_id)

        assert assessment.status == "FAILED"
        assert assessment.current_stage == "report_generation"
        assert assessment.error == "CONTROLLED_REPORT_FAILURE"

    state = checkpoint_state(assessment_id)

    assert "risk_and_checkpoint" in state["completed"]
    assert "report_generation" not in state["completed"]
    assert "report_generation" in state["pending"]
    assert state["state"]["error"] == "CONTROLLED_REPORT_FAILURE"

    assert calls == [
        "markdown",
        "json",
        "html",
    ]


def test_resume_from_report_generation(monkeypatch, tmp_path):
    assessment_id = _make_assessment()

    # Pretend every previous stage has already completed.
    from core.checkpoints import save_checkpoint

    save_checkpoint(
        assessment_id=assessment_id,
        stage="risk_and_checkpoint",
        completed=[
            "scope_validation",
            "web_security",
            "tls_security",
            "nmap_discovery",
            "extended_web",
            "risk_and_checkpoint",
        ],
        pending=[
            "report_generation",
        ],
        state={
            "risks": [],
            "status": "RUNNING",
        },
    )

    generated = []

    def fake_build_report(aid, fmt="markdown"):
        generated.append(fmt)

        path = tmp_path / f"assessment-{aid}.{fmt}"
        path.write_text(
            f"report-{fmt}",
            encoding="utf-8",
        )
        return path

    monkeypatch.setattr(
        orchestrator,
        "build_report",
        fake_build_report,
    )

    orchestrator.run_assessment(
        assessment_id,
        resume=True,
    )

    assert generated == [
        "markdown",
        "json",
        "html",
        "pdf",
    ]

    with SessionLocal() as db:
        assessment = db.get(Assessment, assessment_id)

        assert assessment.status == "COMPLETED"
        assert assessment.current_stage == "completed"
        assert assessment.progress == 100

    state = checkpoint_state(assessment_id)

    assert "report_generation" in state["completed"]
    assert state["pending"] == []


def test_crash_before_report_checkpoint_can_resume(monkeypatch, tmp_path):
    assessment_id = _make_assessment()

    from core.checkpoints import save_checkpoint

    save_checkpoint(
        assessment_id=assessment_id,
        stage="risk_and_checkpoint",
        completed=[
            "scope_validation",
            "web_security",
            "tls_security",
            "nmap_discovery",
            "extended_web",
            "risk_and_checkpoint",
        ],
        pending=[
            "report_generation",
        ],
        state={
            "risks": [],
            "status": "RUNNING",
            "simulated_crash": True,
        },
    )

    calls = {"count": 0}

    def crash_once(aid, fmt="markdown"):
        calls["count"] += 1

        if calls["count"] == 1:
            raise RuntimeError("SIMULATED_REPORT_PROCESS_CRASH")

        path = tmp_path / f"assessment-{aid}-{fmt}.txt"
        path.write_text("ok", encoding="utf-8")
        return path

    monkeypatch.setattr(
        orchestrator,
        "build_report",
        crash_once,
    )

    with pytest.raises(
        RuntimeError,
        match="SIMULATED_REPORT_PROCESS_CRASH",
    ):
        orchestrator.run_assessment(
            assessment_id,
            resume=True,
        )

    failed_state = checkpoint_state(assessment_id)

    assert "report_generation" not in failed_state["completed"]
    assert "report_generation" in failed_state["pending"]

    # Resume from the persisted checkpoint.
    monkeypatch.setattr(
        orchestrator,
        "build_report",
        lambda aid, fmt="markdown": tmp_path / f"resume-{aid}-{fmt}.txt",
    )

    orchestrator.run_assessment(
        assessment_id,
        resume=True,
    )

    with SessionLocal() as db:
        assessment = db.get(Assessment, assessment_id)

        assert assessment.status == "COMPLETED"
        assert assessment.current_stage == "completed"
        assert assessment.progress == 100

    final_state = checkpoint_state(assessment_id)

    assert "report_generation" in final_state["completed"]
    assert final_state["pending"] == []
