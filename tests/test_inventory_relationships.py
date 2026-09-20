import uuid

from core.db import SessionLocal, init_db
from core.inventory import get_or_create_asset, get_or_create_service
from database.models import Assessment, Asset, Finding, Service, Target


def make_assessment():
    init_db()

    db = SessionLocal()

    target = Target(
        name=f"relationship-e2e-target-{uuid.uuid4().hex[:12]}",
        url="http://127.0.0.1:8080",
        ip="127.0.0.1",
    )
    db.add(target)
    db.flush()

    assessment = Assessment(
        target_id=target.id,
        profile="SAFE",
        status="RUNNING",
        current_stage="nmap_discovery",
        progress=50,
    )
    db.add(assessment)
    db.flush()

    return db, assessment


def test_inventory_service_relationship_is_persistent():
    db, assessment = make_assessment()

    try:
        asset = get_or_create_asset(
            db,
            assessment.id,
            "127.0.0.1",
            "HOST",
        )[0]

        service = get_or_create_service(
            db,
            asset.id,
            8080,
            "TCP",
            "http",
            "BaseHTTPServer 0.6",
        )[0]

        db.commit()

        loaded_asset = db.query(Asset).filter(Asset.id == asset.id).first()

        loaded_service = db.query(Service).filter(Service.id == service.id).first()

        assert loaded_asset is not None
        assert loaded_asset.host == "127.0.0.1"
        assert loaded_asset.kind == "HOST"

        assert loaded_service is not None
        assert loaded_service.asset_id == loaded_asset.id
        assert loaded_service.port == 8080
        assert loaded_service.protocol == "TCP"
        assert loaded_service.name == "http"

    finally:
        db.rollback()
        db.close()


def test_finding_can_persist_host_and_service_relationship():
    db, assessment = make_assessment()

    try:
        asset = get_or_create_asset(
            db,
            assessment.id,
            "127.0.0.1",
            "HOST",
        )[0]

        service = get_or_create_service(
            db,
            asset.id,
            8080,
            "TCP",
            "http",
            "BaseHTTPServer 0.6",
        )[0]

        finding = Finding(
            assessment_id=assessment.id,
            fingerprint="relationship-e2e-test",
            title="Relationship test finding",
            severity="LOW",
            confidence="HIGH",
            category="TEST",
            status="DETECTED",
            asset="127.0.0.1",
            evidence="relationship test",
            remediation="test",
            cwe="CWE-693",
            asset_id=asset.id,
            service_id=service.id,
        )

        db.add(finding)
        db.commit()
        db.refresh(finding)

        loaded = db.query(Finding).filter(Finding.id == finding.id).first()

        assert loaded is not None
        assert loaded.asset_id == asset.id
        assert loaded.service_id == service.id

        linked_asset = db.query(Asset).filter(Asset.id == loaded.asset_id).first()

        linked_service = db.query(Service).filter(Service.id == loaded.service_id).first()

        assert linked_asset is not None
        assert linked_asset.host == "127.0.0.1"

        assert linked_service is not None
        assert linked_service.asset_id == linked_asset.id
        assert linked_service.port == 8080

    finally:
        db.rollback()
        db.close()
