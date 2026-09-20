from urllib.parse import urlparse

from database.models import Asset, Service


def find_asset(db, assessment_id: int, host: str, kind: str):
    return (
        db.query(Asset)
        .filter(
            Asset.assessment_id == assessment_id,
            Asset.host == host,
            Asset.kind == kind,
        )
        .first()
    )


def find_service(
    db,
    asset_id: int,
    port: int,
    protocol: str = "TCP",
):
    return (
        db.query(Service)
        .filter(
            Service.asset_id == asset_id,
            Service.port == port,
            Service.protocol == protocol,
        )
        .first()
    )


def resolve_web_relationship(db, assessment_id: int, url: str):
    """
    Resolve a web finding to the WEB_APPLICATION asset.

    The primary lookup uses the exact URL because SentinelAutoSec
    currently stores web application assets using the target URL.
    A hostname fallback is included for future compatibility.
    """
    asset = find_asset(
        db,
        assessment_id,
        url,
        "WEB_APPLICATION",
    )

    if asset is not None:
        return asset, None

    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc

    if host:
        asset = find_asset(
            db,
            assessment_id,
            host,
            "WEB_APPLICATION",
        )

    return asset, None


def resolve_host_service_relationship(
    db,
    assessment_id: int,
    host: str,
    port: int,
    protocol: str = "TCP",
):
    """
    Resolve a network finding to its HOST asset and SERVICE.
    """
    asset = find_asset(
        db,
        assessment_id,
        host,
        "HOST",
    )

    if asset is None:
        return None, None

    service = find_service(
        db,
        asset.id,
        port,
        protocol,
    )

    return asset, service
