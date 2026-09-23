import os
import tempfile

# Isolate every test run from real user data. These variables MUST be set
# before core.config is imported anywhere, because settings snapshot the
# environment at import time. Without this, pytest would write test targets,
# assessments, findings and reports into the user's real database and
# reports/generated directory.
_TEST_DB = os.path.join(tempfile.gettempdir(), "sentinelsec-test.db")
_TEST_REPORTS = os.path.join(tempfile.gettempdir(), "sentinelsec-test-reports")
os.environ["SENTINELSEC_DB"] = _TEST_DB
os.environ["SENTINELSEC_REPORTS"] = _TEST_REPORTS

if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)

import pytest  # noqa: E402

from core.db import init_db  # noqa: E402


@pytest.fixture(autouse=True)
def _ensure_database_schema():
    """
    Guarantee the schema exists before any test runs.

    The test database is a fresh temporary file for this pytest invocation,
    so a database file from a previous run (or from the user's real
    environment) is never reused or polluted.
    """
    init_db()
    yield