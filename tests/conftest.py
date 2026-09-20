import pytest

from core.db import init_db


@pytest.fixture(autouse=True)
def _ensure_database_schema():
    """
    Guarantee the schema exists before any test runs.

    The database file is gitignored, so a fresh checkout (e.g. CI) starts
    with no tables at all. Every DB-touching test must therefore be able
    to rely on init_db() having created the schema.
    """
    init_db()
    yield