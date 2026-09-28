from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from core.config import settings

DB_PATH = settings.db_path
DATABASE_URL = f"sqlite:///{DB_PATH.resolve()}"


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, future=True, connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _apply_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    """
    Tune SQLite for a dashboard that polls while background scans write.

    - WAL keeps readers (dashboard requests) from blocking the scan writer.
    - synchronous=NORMAL stays crash-safe under WAL while avoiding an fsync
      on every transaction.
    - busy_timeout turns momentary lock contention into a short wait instead
      of an immediate "database is locked" error.
    - foreign_keys enforces referential integrity, so deletes must remove
      child rows before their parents (the API does exactly that).
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


# Indexes for the columns the dashboard filters on most (lab filtering and
# job lookups run on every poll). Applied additively to existing databases.
_INDEX_STATEMENTS = (
    "CREATE INDEX IF NOT EXISTS ix_targets_is_lab ON targets (is_lab)",
    "CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs (status)",
    "CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings (severity)",
    "CREATE INDEX IF NOT EXISTS ix_audit_logs_target ON audit_logs (target)",
)


def init_db() -> None:
    from database import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def migrate_schema() -> None:
    """
    Apply small additive schema migrations that SQLAlchemy create_all()
    does not perform on existing tables.

    This migration is intentionally conservative:
    - only adds missing nullable columns
    - only adds missing indexes
    - never drops columns
    - never deletes existing data
    """
    inspector = inspect(engine)

    findings_columns = {column["name"] for column in inspector.get_columns("findings")}
    targets_columns = {column["name"] for column in inspector.get_columns("targets")}

    statements = []
    added_lab_column = False

    if "asset_id" not in findings_columns:
        statements.append("ALTER TABLE findings ADD COLUMN asset_id INTEGER REFERENCES assets(id)")

    if "service_id" not in findings_columns:
        statements.append(
            "ALTER TABLE findings ADD COLUMN service_id INTEGER REFERENCES services(id)"
        )

    if "is_lab" not in targets_columns:
        statements.append("ALTER TABLE targets ADD COLUMN is_lab BOOLEAN NOT NULL DEFAULT 0")
        added_lab_column = True

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

        if added_lab_column:
            # One-time tagging on the very first migration that adds the
            # column: the documented local lab target ("local-lab") is
            # marked as lab data so the dashboard hides it by default.
            # Users can change this later from the dashboard.
            connection.execute(
                text("UPDATE targets SET is_lab = 1 WHERE lower(name) = 'local-lab'")
            )

        for index_statement in _INDEX_STATEMENTS:
            connection.execute(text(index_statement))
