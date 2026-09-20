import json
from datetime import UTC, datetime
from typing import Any

from core.checkpoints import checkpoint_state, save_checkpoint
from core.config import settings
from core.correlation import correlate
from core.db import SessionLocal
from core.finding_links import resolve_web_relationship
from core.inventory import get_or_create_asset, get_or_create_service, inventory_summary
from core.risk import calculate_risk
from core.scope import validate_request, validate_target_for_scan, validate_target_url
from database.models import Assessment, Asset, AuditLog, Evidence, Finding, Service
from integrations.external.nuclei import available as nuclei_available
from integrations.external.nuclei import baseline as nuclei_baseline
from integrations.external.zap import available as zap_available
from integrations.external.zap import baseline as zap_baseline
from integrations.nmap.adapter import available as nmap_available
from integrations.nmap.adapter import scan as nmap_scan
from modules.tls.analyzer import analyze as analyze_tls
from modules.web.http_security import analyze as analyze_web
from reporting.generator import build_report

MODULES = [
    "scope_validation",
    "web_security",
    "tls_security",
    "nmap_discovery",
    "extended_web",
    "risk_and_checkpoint",
    "report_generation",
]


def _has_finding(db, assessment_id, fingerprint):
    """Return an existing finding that correlates with the candidate fingerprint."""
    candidate = {"fingerprint": fingerprint}

    findings = db.query(Finding).filter_by(assessment_id=assessment_id).all()

    for existing in findings:
        if correlate(
            {"fingerprint": existing.fingerprint},
            candidate,
        ):
            return existing

    return None


def _get_asset(db, assessment_id, host, kind):
    return (
        db.query(Asset)
        .filter_by(
            assessment_id=assessment_id,
            host=host,
            kind=kind,
        )
        .first()
    )


def _add_findings(
    db,
    assessment_id,
    asset,
    findings,
    tool,
    evidence,
    asset_id=None,
    service_id=None,
):
    added = 0

    for f in findings:
        if _has_finding(db, assessment_id, f.fingerprint):
            continue

        row = Finding(
            assessment_id=assessment_id,
            fingerprint=f.fingerprint,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            category=f.category,
            status="DETECTED",
            asset=asset,
            evidence=f.evidence,
            remediation=f.remediation,
            cwe=f.cwe,
            asset_id=asset_id,
            service_id=service_id,
        )

        db.add(row)
        db.flush()
        added += 1

        db.add(
            Evidence(
                assessment_id=assessment_id,
                finding_id=row.id,
                tool=tool,
                evidence_type="STRUCTURED",
                content=json.dumps(evidence, default=str),
            )
        )

    return added


def _checkpoint(aid, stage, completed, state=None):
    done = list(dict.fromkeys(completed))
    pending = [m for m in MODULES if m not in done]
    save_checkpoint(aid, stage, done, pending, state or {})


def _build_final_report(assessment_id: int, fmt: str):
    """Build a final report while remaining compatible with legacy test doubles."""
    try:
        return build_report(
            assessment_id,
            fmt,
            status_override="COMPLETED",
            progress_override=100,
        )
    except TypeError as exc:
        message = str(exc)
        if "unexpected keyword argument" not in message or "status_override" not in message:
            raise
        return build_report(assessment_id, fmt)


def run_assessment(assessment_id: int, resume: bool = True) -> None:
    with SessionLocal() as db:
        a = db.get(Assessment, assessment_id)
        if not a:
            raise ValueError("Assessment not found.")
        target = a.target
        if a.status == "COMPLETED":
            return
        state = (
            checkpoint_state(assessment_id)
            if resume
            else {"completed": [], "pending": MODULES, "state": {}}
        )
        completed = set(state.get("completed", []))
        a.status = "RUNNING"
        a.error = None
        if not a.started_at:
            a.started_at = datetime.now(UTC)
        db.commit()
        try:
            validate_target_for_scan(target)
            if "scope_validation" not in completed:
                a.current_stage = "scope_validation"
                a.progress = 5
                db.commit()
                if target.url:
                    _, host, port = validate_target_url(target)
                    validate_request(target, host, port)
                elif target.ip:
                    validate_request(target, target.ip, None)
                else:
                    raise ValueError("Target requires a URL or IP.")
                completed.add("scope_validation")
                _checkpoint(a.id, "scope_validation", completed, {"progress": 5})

            if target.url and "web_security" not in completed:
                a.current_stage = "web_security"
                a.progress = 25
                db.commit()
                findings, evidence = analyze_web(target.url, settings.request_timeout)

                web_asset, web_service = resolve_web_relationship(
                    db,
                    a.id,
                    target.url,
                )

                added = _add_findings(
                    db,
                    a.id,
                    target.url,
                    findings,
                    "HTTPAnalyzer",
                    evidence,
                    asset_id=web_asset.id if web_asset else None,
                    service_id=web_service.id if web_service else None,
                )

                db.commit()
                completed.add("web_security")
                _checkpoint(
                    a.id,
                    "web_security",
                    completed,
                    {
                        "finding_count": len(a.findings),
                        "added": added,
                    },
                )
            if (
                target.url
                and target.url.lower().startswith("https://")
                and "tls_security" not in completed
            ):
                a.current_stage = "tls_security"
                a.progress = 40
                db.commit()
                tls_findings, evidence = analyze_tls(target.url, settings.request_timeout)

                tls_asset, tls_service = resolve_web_relationship(
                    db,
                    a.id,
                    target.url,
                )

                _add_findings(
                    db,
                    a.id,
                    target.url,
                    tls_findings,
                    "TLSAnalyzer",
                    evidence,
                    asset_id=tls_asset.id if tls_asset else None,
                    service_id=tls_service.id if tls_service else None,
                )

                db.commit()
                completed.add("tls_security")
                _checkpoint(
                    a.id,
                    "tls_security",
                    completed,
                    {
                        "finding_count": len(a.findings),
                    },
                )
            elif "tls_security" not in completed:
                completed.add("tls_security")
                _checkpoint(
                    a.id,
                    "tls_security",
                    completed,
                    {
                        "skipped": True,
                    },
                )
            if target.ip and nmap_available() and "nmap_discovery" not in completed:
                a.current_stage = "nmap_discovery"
                a.progress = 60
                db.commit()
                ports = sorted({s.port for s in target.scopes if not s.excluded and s.port})
                asset, _asset_created = get_or_create_asset(
                    db,
                    a.id,
                    target.ip,
                    "HOST",
                )

                discovered_services = nmap_scan(target.ip, ports)

                created_services = 0
                updated_services = 0

                for item in discovered_services:
                    _, created, changed = get_or_create_service(
                        db,
                        asset.id,
                        item["port"],
                        item.get("protocol", "TCP"),
                        item.get("name"),
                        item.get("version"),
                    )

                    if created:
                        created_services += 1
                    elif changed:
                        updated_services += 1

                db.commit()

                completed.add("nmap_discovery")

                count = db.query(Service).filter_by(asset_id=asset.id).count()

                _checkpoint(
                    a.id,
                    "nmap_discovery",
                    completed,
                    {
                        "services": count,
                        "created_services": created_services,
                        "updated_services": updated_services,
                    },
                )
            elif "nmap_discovery" not in completed:
                completed.add("nmap_discovery")
                _checkpoint(a.id, "nmap_discovery", completed, {"skipped": not nmap_available()})

            if target.url and a.profile == "EXTENDED" and "extended_web" not in completed:
                a.current_stage = "extended_web"
                a.progress = 75
                db.commit()
                results: dict[str, Any] = {}
                if nuclei_available():
                    try:
                        results["nuclei"] = nuclei_baseline(target.url)
                    except (OSError, RuntimeError, ValueError) as exc:
                        results["nuclei_error"] = str(exc)
                else:
                    results["nuclei_skipped"] = "not_installed"
                if zap_available():
                    try:
                        results["zap"] = zap_baseline(target.url)
                    except (OSError, RuntimeError, ValueError) as exc:
                        results["zap_error"] = str(exc)
                else:
                    results["zap_skipped"] = "not_installed"
                db.add(
                    Evidence(
                        assessment_id=a.id,
                        finding_id=None,
                        tool="ExternalBaselines",
                        evidence_type="TOOL_OUTPUT",
                        content=json.dumps(results, default=str),
                    )
                )
                db.commit()
                completed.add("extended_web")
                _checkpoint(a.id, "extended_web", completed, {"tools": list(results)})
            elif "extended_web" not in completed:
                completed.add("extended_web")
                _checkpoint(a.id, "extended_web", completed, {"skipped": a.profile != "EXTENDED"})

            if "risk_and_checkpoint" not in completed:
                a.current_stage = "risk_and_checkpoint"
                a.progress = 85
                db.commit()
                risk = [
                    {"id": f.id, "risk": calculate_risk(f.severity, f.confidence)}
                    for f in a.findings
                ]
                completed.add("risk_and_checkpoint")
                _checkpoint(a.id, "risk_and_checkpoint", completed, {"risks": risk})
            else:
                risk = [
                    {"id": f.id, "risk": calculate_risk(f.severity, f.confidence)}
                    for f in a.findings
                ]

            # ---------------------------------------------------------
            # Durable report-generation stage.
            #
            # Report generation is deliberately a real orchestrator
            # stage rather than something merely marked complete in the
            # final checkpoint.
            #
            # If the process crashes before this checkpoint is written,
            # the assessment remains resumable with report_generation
            # still pending.
            # ---------------------------------------------------------
            if "report_generation" not in completed:
                a.current_stage = "report_generation"
                a.progress = 95
                db.commit()

                _checkpoint(
                    a.id,
                    "report_generation",
                    completed,
                    {
                        "status": "REPORT_GENERATION_STARTED",
                        "formats": ["markdown", "json", "html", "pdf"],
                        "risks": risk,
                    },
                )

                generated_reports = {}

                for fmt in ("markdown", "json", "html", "pdf"):
                    path = _build_final_report(a.id, fmt)
                    generated_reports[fmt] = str(path)

                completed.add("report_generation")

                _checkpoint(
                    a.id,
                    "report_generation",
                    completed,
                    {
                        "status": "REPORT_GENERATION_COMPLETED",
                        "formats": list(generated_reports.keys()),
                        "reports": generated_reports,
                        "risks": risk,
                    },
                )
            else:
                generated_reports = {}

            # ---------------------------------------------------------
            # Assessment completion happens only AFTER report
            # generation has successfully completed and been
            # checkpointed.
            # ---------------------------------------------------------
            a.status = "COMPLETED"
            a.current_stage = "completed"
            a.progress = 100
            a.completed_at = datetime.now(UTC)

            db.add(
                AuditLog(
                    action="ASSESSMENT_COMPLETE",
                    target=target.name,
                    result="SUCCESS",
                    details=json.dumps(
                        {
                            "assessment_id": a.id,
                            "finding_count": len(risk),
                            "reports": generated_reports,
                        }
                    ),
                )
            )

            db.commit()

            _checkpoint(
                a.id,
                "completed",
                MODULES,
                {
                    "status": "COMPLETED",
                    "risks": risk,
                    "reports": generated_reports,
                    "inventory": inventory_summary(db, a.id),
                },
            )
        except Exception as exc:
            a.status = "FAILED"
            a.error = str(exc)
            db.add(
                AuditLog(
                    action="SCAN_FAILURE", target=target.name, result="FAILED", details=str(exc)
                )
            )
            db.commit()
            _checkpoint(a.id, a.current_stage or "unknown", list(completed), {"error": str(exc)})
            raise
