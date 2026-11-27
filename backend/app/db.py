import logging
import time
import zlib
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import Request
from sqlalchemy import Engine, MetaData, create_engine, event, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Session

log = logging.getLogger("magma.db")

# Stable constraint names so Alembic migrations work on SQLite and PostgreSQL alike.
NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def normalize_url(url: str) -> str:
    """Accept the usual `postgres://` / `postgresql://` forms and use the bundled psycopg 3."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def is_postgres(url_or_engine) -> bool:
    url = url_or_engine.url if isinstance(url_or_engine, Engine) else url_or_engine
    return str(url).startswith("postgres")


def make_engine(url: str, settings=None) -> Engine:
    url = normalize_url(url)
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record) -> None:  # pragma: no cover - driver hook
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

        return engine

    # PostgreSQL: all timestamps are handled in UTC; long queries can be capped.
    options = "-c timezone=UTC"
    timeout = getattr(settings, "db_statement_timeout_ms", 0) or 0
    if timeout:
        options += f" -c statement_timeout={int(timeout)}"
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=getattr(settings, "db_pool_size", 5),
        max_overflow=getattr(settings, "db_max_overflow", 10),
        pool_recycle=getattr(settings, "db_pool_recycle", 1800),
        pool_timeout=30,
        connect_args={
            "options": options,
            "application_name": "magma-ucf",
            "connect_timeout": 10,
        },
    )


def wait_for_db(engine: Engine, seconds: float = 60) -> None:
    """Retry until the database accepts connections (the Postgres container may start later)."""
    deadline = time.monotonic() + seconds
    delay = 0.5
    while True:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError as e:
            if time.monotonic() >= deadline:
                raise
            log.warning("Database not reachable yet (%s), retrying", str(e).splitlines()[0])
            time.sleep(delay)
            delay = min(delay * 2, 5)


def lock_key(name: str) -> int:
    """A stable 32-bit advisory lock id per job name."""
    return zlib.crc32(f"magma:{name}".encode())


@contextmanager
def exclusive(engine: Engine, name: str) -> Iterator[None]:
    """Hold a cluster-wide lock (several app replicas on one Postgres). No-op on SQLite."""
    if not is_postgres(engine):
        yield
        return
    key = lock_key(name)
    with engine.connect() as conn:
        conn.execute(select(text(f"pg_advisory_lock({key})")))
        conn.commit()
        try:
            yield
        finally:
            conn.execute(select(text(f"pg_advisory_unlock({key})")))
            conn.commit()


def try_job_lock(db: Session, name: str) -> bool:
    """Take a transaction-scoped lock so a background job runs on one replica only.

    Released when the session commits or rolls back. Always True on SQLite.
    """
    if db.bind is None or not is_postgres(db.get_bind()):
        return True
    return bool(db.scalar(select(text(f"pg_try_advisory_xact_lock({lock_key(name)})"))))


def get_db(request: Request) -> Iterator[Session]:
    """One session per request, from the sessionmaker created in app.main.create_app."""
    db: Session = request.app.state.sessionmaker()
    try:
        yield db
    finally:
        db.close()


def lock_row(db: Session, obj) -> None:
    """Reload `obj` and lock its row until the transaction ends (SELECT ... FOR UPDATE).

    Call it right before an optimistic version check: two requests that arrive together then run
    the check one after the other, so the second one sees the first one's version and gets its
    409 instead of silently overwriting it. SQLite has no row locks (writes are serialised) and
    gets a plain reload."""
    db.refresh(obj, with_for_update=True)
