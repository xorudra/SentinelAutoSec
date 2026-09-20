import typer
from rich import print

from core.checkpoints import checkpoint_state
from core.db import SessionLocal, init_db
from core.orchestrator import run_assessment
from database.models import Assessment, Asset, Finding, Service, Target, TargetScope
from integrations.nmap.adapter import available as nmap_available
from reporting.generator import build_report

app = typer.Typer(help="SentinelAutoSec authorized security testing framework.")
target_app = typer.Typer(help="Manage explicitly authorized targets.")
assessment_app = typer.Typer(help="Create, run, resume and inspect assessments.")
app.add_typer(target_app, name="target")
app.add_typer(assessment_app, name="assessment")


@app.command()
def init():
    """Initialize the local database."""
    init_db()
    print("[green]Database initialized.[/green]")


@app.command("tools")
def tools():
    init_db()
    print(f"Nmap: {'available' if nmap_available() else 'not installed'}")


@target_app.command("add")
def target_add(
    name: str,
    url: str = typer.Option(None),
    ip: str = typer.Option(None),
    authorized: bool = typer.Option(False, help="Explicitly mark this target authorized."),
):
    init_db()
    with SessionLocal() as db:
        if db.query(Target).filter_by(name=name).first():
            raise typer.BadParameter("Target name already exists.")
        if not url and not ip:
            raise typer.BadParameter("Provide --url or --ip.")
        t = Target(name=name, url=url, ip=ip, authorization_status=authorized)
        db.add(t)
        db.commit()
        db.refresh(t)
        print(f"Created target {t.id}: {name}")


@target_app.command("list")
def target_list():
    init_db()
    with SessionLocal() as db:
        for t in db.query(Target).all():
            print(f"{t.id}: {t.name} authorized={t.authorization_status} url={t.url} ip={t.ip}")


@target_app.command("scope-add")
def scope_add(
    name: str,
    host: str = typer.Argument(...),
    port: int = typer.Argument(...),
    excluded: bool = typer.Option(False, help="Explicitly exclude this host/port."),
):
    init_db()
    with SessionLocal() as db:
        t = db.query(Target).filter_by(name=name).first()
        if not t:
            raise typer.BadParameter("Target not found.")
        db.add(TargetScope(target_id=t.id, host=host, port=port, excluded=excluded))
        db.commit()
        print("Scope entry added.")


@assessment_app.command("create")
def assessment_create(target: str):
    init_db()
    with SessionLocal() as db:
        t = db.query(Target).filter_by(name=target).first()
        if not t:
            raise typer.BadParameter("Target not found.")
        a = Assessment(target_id=t.id, profile="SAFE")
        db.add(a)
        db.commit()
        db.refresh(a)
        print(f"Assessment #{a.id} created.")


@assessment_app.command("start")
def assessment_start(assessment_id: int):
    init_db()
    run_assessment(assessment_id)
    print(f"[green]Assessment #{assessment_id} completed.[/green]")


@assessment_app.command("resume")
def assessment_resume(assessment_id: int):
    """Resume an interrupted assessment from its latest durable checkpoint."""
    init_db()
    run_assessment(assessment_id, resume=True)
    print(f"[green]Assessment #{assessment_id} resumed/completed.[/green]")


@assessment_app.command("status")
def assessment_status(assessment_id: int):
    """Show assessment state and latest durable checkpoint."""
    init_db()
    with SessionLocal() as db:
        a = db.get(Assessment, assessment_id)
        if not a:
            raise typer.BadParameter("Assessment not found.")
        print(
            {
                "id": a.id,
                "status": a.status,
                "stage": a.current_stage,
                "progress": a.progress,
                "error": a.error,
                "checkpoint": checkpoint_state(a.id),
            }
        )


@app.command("scan")
def scan(target: str):
    init_db()
    with SessionLocal() as db:
        t = db.query(Target).filter_by(name=target).first()
        if not t:
            raise typer.BadParameter("Target not found.")
        a = Assessment(target_id=t.id, profile="SAFE")
        db.add(a)
        db.commit()
        db.refresh(a)
        aid = a.id
    run_assessment(aid)
    print(f"[green]Assessment #{aid} completed.[/green]")


@app.command("findings")
def findings(assessment_id: int = typer.Option(None)):
    """Show findings with their related asset and service inventory context."""
    init_db()

    with SessionLocal() as db:
        q = db.query(Finding)

        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)

        rows = q.order_by(Finding.id).all()

        if not rows:
            print("[yellow]No findings found.[/yellow]")
            return

        for f in rows:
            print(f"#{f.id} [{f.severity}] {f.title}")
            print(f"    Asset:   {f.asset}")

            asset = None
            service = None

            if f.asset_id:
                asset = db.get(Asset, f.asset_id)

            if f.service_id:
                service = db.get(Service, f.service_id)

            if asset:
                print(f"    Type:    {asset.kind}")

            if service:
                print(f"    Service: {service.protocol}/{service.port}")

                if service.name:
                    print(f"    Name:    {service.name}")

                if service.version:
                    print(f"    Version: {service.version}")

            print()


@app.command("report")
def report(assessment_id: int = typer.Option(None), fmt: str = typer.Option("markdown")):
    init_db()
    if assessment_id is None:
        with SessionLocal() as db:
            a = db.query(Assessment).order_by(Assessment.id.desc()).first()
            if not a:
                raise typer.BadParameter("No assessments exist.")
            assessment_id = a.id
    path = build_report(assessment_id, fmt)
    print(f"[green]Report: {path}[/green]")


if __name__ == "__main__":
    app()
