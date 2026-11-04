import os
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("AUDIT_HMAC_KEY", "test-key-test-key-test-key-test-key-0123")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("OPERATOR_PASSWORD", "test-operator-password")
os.environ.setdefault("CLASSIFIER_TOKEN", "test-classifier-token")
os.environ.setdefault("COOKIE_SECURE", "0")
os.environ.setdefault("SENTINEL_CONFIG", str(ROOT / "config" / "config.json"))

TEST_DB = os.environ.get("TEST_DATABASE_URL")
if TEST_DB:
    os.environ["DATABASE_URL"] = TEST_DB


@pytest.fixture(scope="session")
def pol():
    from sentinel.config import load_policy

    return load_policy(ROOT / "config" / "config.json")


@pytest.fixture()
def engine():
    if not TEST_DB:
        pytest.skip("TEST_DATABASE_URL is not set")
    from sentinel import db

    db.get_engine.cache_clear()
    eng = db.get_engine()
    with eng.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA public CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA public"))
    db.migrate(eng)
    yield eng
