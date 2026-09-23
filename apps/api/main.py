from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, HttpUrl

from core.checkpoints import checkpoint_state
from core.config import settings
from core.db import SessionLocal, init_db, migrate_schema
from core.jobs import job_status, submit_assessment
from core.orchestrator import run_assessment
from database.models import (
    Assessment,
    Asset,
    AuditLog,
    Evidence,
    Finding,
    Job,
    Service,
    Target,
    TargetScope,
)
from integrations.external.nuclei import available as nuclei_available
from integrations.external.zap import available as zap_available
from integrations.nmap.adapter import available as nmap_available
from reporting.generator import build_report


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    # Additive schema migrations for databases created by older versions.
    migrate_schema()

    from core.jobs import recover_stale_jobs

    # First recover jobs whose workers disappeared.
    recover_stale_jobs()

    # Then start queued jobs.
    with SessionLocal() as db:
        queued = [j.assessment_id for j in db.query(Job).filter(Job.status == "QUEUED").all()]

    for assessment_id in queued:
        submit_assessment(assessment_id)

    yield


app = FastAPI(
    title="SentinelAutoSec API",
    version="1.1.0",
    description="Authorized security assessment automation with strict scope enforcement.",
    lifespan=lifespan,
)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: HttpUrl | None = None
    ip: str | None = None
    authorized: bool = False
    is_lab: bool = False


class TargetLabUpdate(BaseModel):
    is_lab: bool


class ScopeCreate(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    excluded: bool = False


class AssessmentCreate(BaseModel):
    target_id: int = Field(gt=0)
    profile: str = Field(default="SAFE", pattern="^(SAFE|EXTENDED)$")


def auth(x_api_key: str | None = Header(default=None)):
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(401, "Invalid API key")


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/tools", dependencies=[Depends(auth)])
def tools():
    return {"nmap": nmap_available(), "nuclei": nuclei_available(), "zap_baseline": zap_available()}


@app.post("/targets", dependencies=[Depends(auth)])
def create_target(data: TargetCreate):
    if not data.url and not data.ip:
        raise HTTPException(400, "Provide url or ip.")
    with SessionLocal() as db:
        if db.query(Target).filter_by(name=data.name).first():
            raise HTTPException(409, "Target name already exists")
        t = Target(
            name=data.name,
            url=str(data.url) if data.url else None,
            ip=data.ip,
            authorization_status=data.authorized,
            is_lab=data.is_lab,
        )
        db.add(t)
        db.commit()
        db.refresh(t)
        db.add(AuditLog(action="TARGET_CREATE", target=t.name, result="SUCCESS"))
        db.commit()
        return {"id": t.id, "name": t.name}


@app.get("/targets", dependencies=[Depends(auth)])
def list_targets(include_lab: bool = False):
    with SessionLocal() as db:
        q = db.query(Target)
        if not include_lab:
            q = q.filter(Target.is_lab.is_(False))
        return [
            {
                "id": t.id,
                "name": t.name,
                "authorized": t.authorization_status,
                "is_lab": t.is_lab,
                "url": t.url,
                "ip": t.ip,
                "scope": [
                    {"host": s.host, "port": s.port, "excluded": s.excluded} for s in t.scopes
                ],
            }
            for t in q.all()
        ]


@app.post("/targets/{target_id}/lab", dependencies=[Depends(auth)])
def set_target_lab(target_id: int, data: TargetLabUpdate):
    with SessionLocal() as db:
        t = db.get(Target, target_id)
        if not t:
            raise HTTPException(404, "Target not found")
        t.is_lab = data.is_lab
        db.commit()
        db.add(
            AuditLog(
                action="TARGET_LAB_UPDATE",
                target=t.name,
                result="SUCCESS",
                details=f"is_lab={data.is_lab}",
            )
        )
        db.commit()
        return {"id": t.id, "name": t.name, "is_lab": t.is_lab}


@app.post("/targets/{target_id}/scope", dependencies=[Depends(auth)])
def add_scope(target_id: int, data: ScopeCreate):
    with SessionLocal() as db:
        t = db.get(Target, target_id)
        if not t:
            raise HTTPException(404, "Target not found")
        db.add(
            TargetScope(target_id=target_id, host=data.host, port=data.port, excluded=data.excluded)
        )
        db.commit()
        db.add(
            AuditLog(
                action="SCOPE_UPDATE",
                target=t.name,
                result="SUCCESS",
                details=f"{data.host}:{data.port} excluded={data.excluded}",
            )
        )
        db.commit()
        return {"status": "created"}


@app.post("/assessments", dependencies=[Depends(auth)])
def create_assessment(data: AssessmentCreate):
    with SessionLocal() as db:
        t = db.get(Target, data.target_id)
        if not t:
            raise HTTPException(404, "Target not found")
        a = Assessment(target_id=t.id, profile=data.profile)
        db.add(a)
        db.commit()
        db.refresh(a)
        return {"id": a.id, "status": a.status, "profile": a.profile}


@app.post("/assessments/{assessment_id}/start", dependencies=[Depends(auth)])
def start_assessment(assessment_id: int, background: bool = True):
    with SessionLocal() as db:
        a = db.get(Assessment, assessment_id)
        if not a:
            raise HTTPException(404, "Assessment not found")
    if background:
        submit_assessment(assessment_id)
        return {"id": assessment_id, "status": "QUEUED"}
    try:
        run_assessment(assessment_id)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        # Unexpected failures (e.g. network errors from scanners) must still
        # produce a defined API response instead of an unhandled 500 traceback.
        raise HTTPException(500, f"Assessment failed: {exc}") from exc
    return {"id": assessment_id, "status": "COMPLETED"}


@app.post("/assessments/{assessment_id}/resume", dependencies=[Depends(auth)])
def resume_assessment(assessment_id: int):
    with SessionLocal() as db:
        if not db.get(Assessment, assessment_id):
            raise HTTPException(404, "Assessment not found")
    submit_assessment(assessment_id)
    return {"id": assessment_id, "status": "QUEUED", "checkpoint": checkpoint_state(assessment_id)}


@app.get("/assessments", dependencies=[Depends(auth)])
def assessments(include_lab: bool = False):
    with SessionLocal() as db:
        q = db.query(Assessment)
        if not include_lab:
            q = q.join(Target, Assessment.target_id == Target.id).filter(
                Target.is_lab.is_(False)
            )
        return [
            {
                "id": a.id,
                "target_id": a.target_id,
                "status": a.status,
                "profile": a.profile,
                "stage": a.current_stage,
                "progress": a.progress,
                "error": a.error,
                "job": job_status(a.id),
            }
            for a in q.all()
        ]


@app.get("/assessments/{assessment_id}/checkpoint", dependencies=[Depends(auth)])
def checkpoint(assessment_id: int):
    with SessionLocal() as db:
        if not db.get(Assessment, assessment_id):
            raise HTTPException(404, "Assessment not found")
    return checkpoint_state(assessment_id)


@app.get("/findings", dependencies=[Depends(auth)])
def list_findings(assessment_id: int | None = None, include_lab: bool = False):
    with SessionLocal() as db:
        q = db.query(Finding)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        if not include_lab:
            q = (
                q.join(Assessment, Finding.assessment_id == Assessment.id)
                .join(Target, Assessment.target_id == Target.id)
                .filter(Target.is_lab.is_(False))
            )
        return [
            {
                "id": f.id,
                "assessment_id": f.assessment_id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
                "asset": f.asset,
                "status": f.status,
                "cwe": f.cwe,
            }
            for f in q.order_by(Finding.id).all()
        ]


@app.get("/findings/{finding_id}", dependencies=[Depends(auth)])
def finding_detail(finding_id: int):
    with SessionLocal() as db:
        f = db.get(Finding, finding_id)
        if not f:
            raise HTTPException(404, "Finding not found")
        return {
            "id": f.id,
            "assessment_id": f.assessment_id,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "category": f.category,
            "asset": f.asset,
            "status": f.status,
            "cwe": f.cwe,
            "evidence": f.evidence,
            "remediation": f.remediation,
        }


@app.get("/evidence", dependencies=[Depends(auth)])
def evidence(assessment_id: int | None = None):
    with SessionLocal() as db:
        q = db.query(Evidence)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        return [
            {
                "id": e.id,
                "assessment_id": e.assessment_id,
                "finding_id": e.finding_id,
                "tool": e.tool,
                "type": e.evidence_type,
                "content": e.content,
                "collected_at": e.collected_at.isoformat(),
            }
            for e in q.order_by(Evidence.id).all()
        ]


@app.get("/assets", dependencies=[Depends(auth)])
def assets(assessment_id: int | None = None):
    with SessionLocal() as db:
        q = db.query(Asset)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        return [
            {
                "id": a.id,
                "assessment_id": a.assessment_id,
                "host": a.host,
                "kind": a.kind,
                "services": [
                    {
                        "id": s.id,
                        "port": s.port,
                        "protocol": s.protocol,
                        "name": s.name,
                        "version": s.version,
                    }
                    for s in db.query(Service).filter_by(asset_id=a.id).all()
                ],
            }
            for a in q.all()
        ]


@app.get("/audit-logs", dependencies=[Depends(auth)])
def audit_logs(include_lab: bool = False):
    with SessionLocal() as db:
        q = db.query(AuditLog).order_by(AuditLog.id.desc())
        if not include_lab:
            lab_names = [
                row[0] for row in db.query(Target.name).filter(Target.is_lab.is_(True)).all()
            ]
            if lab_names:
                q = q.filter(AuditLog.target.notin_(lab_names))
        return [
            {
                "id": x.id,
                "actor": x.actor,
                "action": x.action,
                "target": x.target,
                "result": x.result,
                "details": x.details,
                "created_at": x.created_at.isoformat(),
            }
            for x in q.limit(200)
        ]


@app.post("/reports", dependencies=[Depends(auth)])
def create_report(assessment_id: int, fmt: str = "markdown"):
    try:
        path = build_report(assessment_id, fmt)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    with SessionLocal() as db:
        a = db.get(Assessment, assessment_id)
        if a:
            db.add(
                AuditLog(
                    action="REPORT_CREATE",
                    target=a.target.name,
                    result="SUCCESS",
                    details=f"format={fmt}",
                )
            )
            db.commit()
    return {"path": str(path)}


@app.get("/reports/view", dependencies=[Depends(auth)])
def view_report(assessment_id: int, fmt: str = "html"):
    fmt = fmt.lower()
    suffix = {"markdown": "md"}.get(fmt, fmt)
    if suffix not in {"md", "json", "html", "pdf"}:
        raise HTTPException(400, "Format must be markdown, json, html, or pdf.")
    path = settings.reports_dir / f"assessment-{assessment_id}.{suffix}"
    if not path.exists():
        raise HTTPException(404, "Report not found. Generate it first.")
    media = {
        "html": "text/html",
        "json": "application/json",
        "pdf": "application/pdf",
        "md": "text/markdown",
    }
    return FileResponse(path, media_type=media[suffix], filename=path.name)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with SessionLocal() as db:
        targets = db.query(Target).count()
        assessments_n = db.query(Assessment).count()
        findings = db.query(Finding).count()
        critical = db.query(Finding).filter(Finding.severity == "CRITICAL").count()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "targets": targets,
            "assessments": assessments_n,
            "findings": findings,
            "critical": critical,
        },
    )
