from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from core.config import settings

DB_PATH = settings.db_path
DATABASE_URL = f"sqlite:///{DB_PATH.resolve()}"


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, future=True, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    from database import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def migrate_schema() -> None:
    """
    Apply small additive schema migrations that SQLAlchemy create_all()
    does not perform on existing tables.

    This migration is intentionally conservative:
    - only adds missing nullable columns
    - never drops columns
    - never deletes existing data
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)

    findings_columns = {column["name"] for column in inspector.get_columns("findings")}

    statements = []

    if "asset_id" not in findings_columns:
        statements.append("ALTER TABLE findings ADD COLUMN asset_id INTEGER REFERENCES assets(id)")

    if "service_id" not in findings_columns:
        statements.append(
            "ALTER TABLE findings ADD COLUMN service_id INTEGER REFERENCES services(id)"
        )

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
