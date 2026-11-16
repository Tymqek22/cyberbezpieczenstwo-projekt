import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from testcontainers.community.postgres import PostgresContainer

from app.config import settings

# Throwaway PostgreSQL container for the whole test session. app.db creates the engine
# at import time, so the URL must be set before importing it.
postgres = PostgresContainer("postgres:16", driver="psycopg").start()
settings.database_url = postgres.get_connection_url()
settings.security_log_file = str(Path(tempfile.mkdtemp()) / "security.log")
settings.canary_account_url = "https://canary.invalid/token"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app import rbac  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security import captcha, honeytoken  # noqa: E402
from app.models import Role, User  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402
from scripts.seed import seed_rbac  # noqa: E402

PASSWORD = "bardzo dlugie haslo testowe"

# Turnstile is replaced in tests (no network): VALID_TOKEN passes, anything else fails.
VALID_TOKEN = "test-turnstile-token"
CAPTCHA = {captcha.TOKEN_FIELD: VALID_TOKEN}


def pytest_unconfigure(config):
    engine.dispose()
    postgres.stop()


@pytest.fixture(scope="session", autouse=True)
def schema():
    Base.metadata.create_all(engine)


@pytest.fixture(autouse=True)
def clean_db():
    with engine.begin() as conn:
        tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    with SessionLocal() as db:
        seed_rbac(db)
    yield


@pytest.fixture(autouse=True)
def fake_turnstile(monkeypatch):
    calls = []

    def verify(token, remote_ip=None):
        calls.append(token)
        return token == VALID_TOKEN

    monkeypatch.setattr(captcha, "verify_turnstile", verify)
    return calls


@pytest.fixture(autouse=True)
def canary_calls(monkeypatch):
    """Records Canarytokens triggers instead of sending HTTP requests."""
    calls = []
    monkeypatch.setattr(honeytoken, "trigger_account_canary", lambda *args: calls.append(args))
    return calls


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def make_user(db):
    def _make(login: str, role_name: str, password: str = PASSWORD, **kwargs) -> User:
        role = db.query(Role).filter_by(name=role_name).one()
        user = User(
            login=login,
            first_name="Jan",
            last_name="Test",
            email=f"{login}@example.com",
            role=role,
            password_hash=hash_password(password),
            must_change_password=kwargs.pop("must_change_password", False),
            password_changed_at=datetime.now(timezone.utc),
            **kwargs,
        )
        db.add(user)
        db.commit()
        return user

    return _make


@pytest.fixture
def admin(make_user):
    return make_user("ADMIN", rbac.ROLE_ADMIN, is_system=True)


def login(client: TestClient, user_login: str, password: str = PASSWORD, **extra):
    return client.post("/login", data={"login": user_login, "password": password, **CAPTCHA, **extra})


def csrf_from(client: TestClient, url: str = "/account/change-password") -> str:
    html = client.get(url).text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
