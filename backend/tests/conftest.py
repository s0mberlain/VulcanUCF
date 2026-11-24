import os

# Startup refuses a missing or weak SECRET_KEY (app/config.py); tests use a fixed strong one.
os.environ.setdefault("SECRET_KEY", "test-secret-key-0123456789-abcdefghijklmnop")

import shutil

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app import security
from app.config import Settings
from app.db import make_engine
from app.main import create_app
from app.startup import initialize

ADMIN_PW = "admin-password-123"

# Cheap password hashes: the suite signs in hundreds of times. Hashes still carry their own
# parameters, so verification works the same way; production keeps the argon2 defaults.
security._hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)


# Run the suite against PostgreSQL with TEST_DATABASE_URL=postgresql+psycopg://user:pw@host/db.
# The database is emptied before each test.
PG_URL = os.environ.get("TEST_DATABASE_URL", "")


def _reset_postgres(url: str) -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


@pytest.fixture
def db_url(tmp_path) -> str:
    if PG_URL:
        _reset_postgres(PG_URL)
        return PG_URL
    return f"sqlite:///{tmp_path}/test.db"


@pytest.fixture(scope="session")
def _sqlite_template(tmp_path_factory) -> str:
    """One migrated and seeded SQLite file per test run; each test starts from a copy of it
    instead of running all migrations and the catalogue seed again."""
    path = tmp_path_factory.mktemp("template") / "template.db"
    s = _settings(f"sqlite:///{path}", path.parent / "static")
    engine = make_engine(s.database_url, s)
    initialize(engine, sessionmaker(bind=engine, expire_on_commit=False), s)
    with engine.connect() as conn:  # everything in the main file, nothing left in the WAL
        conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
    engine.dispose()
    return str(path)


@pytest.fixture
def app_db_url(request, tmp_path) -> str:
    """The database the app fixtures use: a copy of the template on SQLite."""
    if PG_URL:
        return request.getfixturevalue("db_url")
    target = tmp_path / "app.db"
    shutil.copyfile(request.getfixturevalue("_sqlite_template"), target)
    return f"sqlite:///{target}"


def _settings(url: str, static_dir) -> Settings:
    return Settings(
        database_url=url,
        static_dir=static_dir,
        admin_user="admin",
        admin_password=ADMIN_PW,
        snapshot_schedule="off",
        allow_demo_data=True,
    )


@pytest.fixture
def settings(tmp_path, app_db_url) -> Settings:
    return _settings(app_db_url, tmp_path / "static")


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def anon(app):
    with TestClient(app) as c:
        yield c


def login(client: TestClient, username: str, password: str) -> TestClient:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return client


@pytest.fixture
def admin(app):
    with TestClient(app) as c:
        yield login(c, "admin", ADMIN_PW)


@pytest.fixture
def make_user(app, admin):
    clients = []

    def _make(role: str, username: str | None = None) -> TestClient:
        username = username or f"{role}1"
        pw = f"{role}-password-123"
        r = admin.post("/api/users", json={"username": username, "role": role, "password": pw})
        assert r.status_code == 201, r.text
        c = TestClient(app)
        clients.append(c)
        return login(c, username, pw)

    yield _make
    for c in clients:
        c.close()
