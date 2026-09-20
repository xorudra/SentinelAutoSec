import uuid

from core.db import SessionLocal, init_db
from core.inventory import (
    get_or_create_asset,
    get_or_create_service,
    inventory_summary,
)
from database.models import Assessment, Target


def create_test_assessment(db, name):
    # Every test run gets a unique Target.name because
    # Target.name has a database-level UNIQUE constraint.
    unique_name = f"{name}-{uuid.uuid4().hex[:12]}"

    target = Target(
        name=unique_name,
        hostname="inventory-test.local",
        ip="127.0.0.1",
        url="http://127.0.0.1:8080",
        target_type="WEB_APPLICATION",
        environment="TEST",
        authorization_status=True,
    )

    db.add(target)
    db.flush()

    assessment = Assessment(
        target_id=target.id,
        profile="SAFE",
        status="QUEUED",
        progress=0,
    )

    db.add(assessment)
    db.flush()

    return assessment.id


def test_asset_creation_is_idempotent():
    init_db()

    with SessionLocal() as db:
        assessment_id = create_test_assessment(
            db,
            "inventory-test-asset-idempotent",
        )
        db.commit()

        asset1, created1 = get_or_create_asset(
            db,
            assessment_id,
            "inventory-test-host",
            "HOST",
        )
        db.commit()

        asset2, created2 = get_or_create_asset(
            db,
            assessment_id,
            "inventory-test-host",
            "HOST",
        )
        db.commit()

        assert asset1.id == asset2.id
        assert created1 is True
        assert created2 is False


def test_service_creation_is_idempotent():
    init_db()

    with SessionLocal() as db:
        assessment_id = create_test_assessment(
            db,
            "inventory-test-service-idempotent",
        )

        asset, asset_created = get_or_create_asset(
            db,
            assessment_id,
            "inventory-service-host",
            "HOST",
        )

        assert asset_created is True

        service1, created1, changed1 = get_or_create_service(
            db,
            asset.id,
            8080,
            "tcp",
            "http",
            "Python",
        )
        db.commit()

        service2, created2, changed2 = get_or_create_service(
            db,
            asset.id,
            8080,
            "TCP",
            "http",
            "Python",
        )
        db.commit()

        assert service1.id == service2.id
        assert created1 is True
        assert created2 is False
        assert changed1 is True
        assert changed2 is False


def test_service_metadata_can_be_updated():
    init_db()

    with SessionLocal() as db:
        assessment_id = create_test_assessment(
            db,
            "inventory-test-service-update",
        )

        asset, asset_created = get_or_create_asset(
            db,
            assessment_id,
            "inventory-update-host",
            "HOST",
        )

        assert asset_created is True

        service, created, changed = get_or_create_service(
            db,
            asset.id,
            443,
            "TCP",
            "https",
            None,
        )
        db.commit()

        assert created is True
        assert changed is True
        assert service.name == "https"
        assert service.version is None

        service2, created2, changed2 = get_or_create_service(
            db,
            asset.id,
            443,
            "tcp",
            "https",
            "OpenSSL",
        )
        db.commit()

        assert service2.id == service.id
        assert created2 is False
        assert changed2 is True
        assert service2.name == "https"
        assert service2.version == "OpenSSL"


def test_inventory_summary_contains_assets_and_services():
    init_db()

    with SessionLocal() as db:
        assessment_id = create_test_assessment(
            db,
            "inventory-test-summary",
        )

        asset, asset_created = get_or_create_asset(
            db,
            assessment_id,
            "inventory-summary-host",
            "HOST",
        )

        assert asset_created is True

        _service, created, changed = get_or_create_service(
            db,
            asset.id,
            8080,
            "TCP",
            "http",
            "Python",
        )

        assert created is True
        assert changed is True

        db.commit()

        summary = inventory_summary(
            db,
            assessment_id,
        )

        assert summary["asset_count"] == 1
        assert summary["service_count"] == 1
        assert len(summary["assets"]) == 1

        assert summary["assets"][0]["host"] == "inventory-summary-host"
        assert summary["assets"][0]["kind"] == "HOST"

        assert len(summary["assets"][0]["services"]) == 1

        assert summary["assets"][0]["services"][0]["port"] == 8080
        assert summary["assets"][0]["services"][0]["protocol"] == "TCP"
        assert summary["assets"][0]["services"][0]["name"] == "http"
        assert summary["assets"][0]["services"][0]["version"] == "Python"
