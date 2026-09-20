from uuid import uuid4

from core.db import SessionLocal, init_db
from core.finding_links import (
    find_asset,
    find_service,
    resolve_host_service_relationship,
    resolve_web_relationship,
)
from core.inventory import get_or_create_asset, get_or_create_service
from database.models import Assessment, Finding, Target


def make_target(db):
    target = Target(
        name=f"relationship-{uuid4().hex}",
        url="http://127.0.0.1:8080",
        ip="127.0.0.1",
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def make_assessment(db):
    target = make_target(db)

    assessment = Assessment(
        target_id=target.id,
        profile="SAFE",
        status="CREATED",
        current_stage="",
        progress=0,
    )

    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    return assessment


def test_web_relationship_resolves_asset():
    init_db()

    with SessionLocal() as db:
        assessment = make_assessment(db)

        asset, _ = get_or_create_asset(
            db,
            assessment.id,
            "http://127.0.0.1:8080",
            "WEB_APPLICATION",
        )

        db.commit()

        resolved_asset, resolved_service = resolve_web_relationship(
            db,
            assessment.id,
            "http://127.0.0.1:8080",
        )

        assert resolved_asset is not None
        assert resolved_asset.id == asset.id
        assert resolved_service is None


def test_host_service_relationship_resolves_both():
    init_db()

    with SessionLocal() as db:
        assessment = make_assessment(db)

        asset, _ = get_or_create_asset(
            db,
            assessment.id,
            "127.0.0.1",
            "HOST",
        )

        service, _, _ = get_or_create_service(
            db,
            asset.id,
            8080,
            "TCP",
            "http",
            "0.6",
        )

        db.commit()

        resolved_asset, resolved_service = resolve_host_service_relationship(
            db,
            assessment.id,
            "127.0.0.1",
            8080,
            "TCP",
        )

        assert resolved_asset is not None
        assert resolved_service is not None
        assert resolved_asset.id == asset.id
        assert resolved_service.id == service.id


def test_finding_relationship_columns_accept_inventory_ids():
    init_db()

    with SessionLocal() as db:
        assessment = make_assessment(db)

        asset, _ = get_or_create_asset(
            db,
            assessment.id,
            "http://127.0.0.1:8080",
            "WEB_APPLICATION",
        )

        service, _, _ = get_or_create_service(
            db,
            asset.id,
            8080,
            "TCP",
            "http",
            "0.6",
        )

        finding = Finding(
            assessment_id=assessment.id,
            fingerprint=f"relationship-test-{uuid4().hex}",
            title="Relationship test finding",
            severity="LOW",
            confidence="HIGH",
            category="TEST",
            status="DETECTED",
            asset="http://127.0.0.1:8080",
            evidence="test",
            remediation="test",
            cwe=None,
            asset_id=asset.id,
            service_id=service.id,
        )

        db.add(finding)
        db.commit()
        db.refresh(finding)

        assert finding.asset_id == asset.id
        assert finding.service_id == service.id


def test_unknown_asset_returns_none():
    init_db()

    with SessionLocal() as db:
        assessment = make_assessment(db)

        result = find_asset(
            db,
            assessment.id,
            "does-not-exist",
            "HOST",
        )

        assert result is None


def test_unknown_service_returns_none():
    init_db()

    with SessionLocal() as db:
        assessment = make_assessment(db)

        asset, _ = get_or_create_asset(
            db,
            assessment.id,
            "127.0.0.1",
            "HOST",
        )

        db.commit()

        result = find_service(
            db,
            asset.id,
            65535,
            "TCP",
        )

        assert result is None
