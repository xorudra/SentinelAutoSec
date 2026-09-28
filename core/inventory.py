"""
Asset and service inventory helpers.

These helpers maintain an assessment-local inventory of discovered
hosts, web applications, and network services.

They are deliberately idempotent so repeated discovery or checkpoint
resume does not create duplicate assets/services.
"""

from database.models import Asset, Service


def get_or_create_asset(db, assessment_id: int, host: str, kind: str):
    """Return an existing assessment asset or create it."""
    asset = (
        db.query(Asset)
        .filter_by(
            assessment_id=assessment_id,
            host=host,
            kind=kind,
        )
        .first()
    )

    if asset:
        return asset, False

    asset = Asset(
        assessment_id=assessment_id,
        host=host,
        kind=kind,
    )

    db.add(asset)
    db.flush()

    return asset, True


def get_or_create_service(
    db,
    asset_id: int,
    port: int,
    protocol: str = "TCP",
    name: str | None = None,
    version: str | None = None,
):
    """Return an existing service or create/update its metadata."""

    protocol = (protocol or "TCP").upper()

    service = (
        db.query(Service)
        .filter_by(
            asset_id=asset_id,
            port=port,
            protocol=protocol,
        )
        .first()
    )

    if service:
        changed = False

        if name and service.name != name:
            service.name = name
            changed = True

        if version and service.version != version:
            service.version = version
            changed = True

        return service, False, changed

    service = Service(
        asset_id=asset_id,
        port=port,
        protocol=protocol,
        name=name,
        version=version,
    )

    db.add(service)
    db.flush()

    return service, True, True


def inventory_summary(db, assessment_id: int) -> dict:
    """Return a structured summary of discovered assets and services.

    Assets and services are fetched with two queries total (instead of one
    services query per asset) and grouped in Python.
    """

    assets = db.query(Asset).filter_by(assessment_id=assessment_id).order_by(Asset.id).all()

    services_by_asset: dict[int, list[Service]] = {}

    if assets:
        service_rows = (
            db.query(Service)
            .filter(Service.asset_id.in_([asset.id for asset in assets]))
            .order_by(Service.port, Service.protocol)
            .all()
        )

        for service in service_rows:
            services_by_asset.setdefault(service.asset_id, []).append(service)

    result = [
        {
            "id": asset.id,
            "host": asset.host,
            "kind": asset.kind,
            "services": [
                {
                    "id": service.id,
                    "port": service.port,
                    "protocol": service.protocol,
                    "name": service.name,
                    "version": service.version,
                }
                for service in services_by_asset.get(asset.id, [])
            ],
        }
        for asset in assets
    ]

    return {
        "asset_count": len(result),
        "service_count": sum(len(asset["services"]) for asset in result),
        "assets": result,
    }
