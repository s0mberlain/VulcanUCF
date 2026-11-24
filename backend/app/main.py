import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from swagger_ui_bundle import swagger_ui_path

from app import __version__, gitsync
from app import snapshots as snapshot_jobs
from app.api import (
    admin,
    app_settings,
    attack_api,
    audit_log,
    auth,
    bulk,
    business,
    configs,
    evidence,
    gitsync_api,
    integrations,
    lifecycle,
    log_sources,
    oidc,
    output,
    priorities,
    purple,
    rounds,
    scores,
    snapshots,
    systems,
    tasks,
    transfer,
    usecases,
    users,
)
from app.config import Settings, check_secret_key, get_settings
from app.db import make_engine
from app.middleware import SecurityHeaders
from app.ratelimit import FailureLimiter
from app.security import Reader
from app.startup import initialize

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

DOCS_ASSETS = {"swagger-ui-bundle.js", "swagger-ui.css", "favicon-32x32.png"}

system = APIRouter(tags=["system"])


@system.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@system.get("/ready")
def ready(request: Request) -> dict[str, str]:
    """Readiness: the database answers. For load balancers and orchestrators."""
    engine = request.app.state.engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except SQLAlchemyError as e:
        raise HTTPException(503, "Database not reachable") from e
    return {"status": "ok", "database": engine.dialect.name}


@system.get("/version")
def version() -> dict[str, str]:
    return {"name": get_settings().app_name, "version": __version__}


def _mount_frontend(app: FastAPI, static_dir: Path) -> None:
    """Serve the built single-page app; unknown non-API paths fall back to index.html."""
    index = static_dir / "index.html"
    if not index.is_file():
        return

    assets = static_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    root = static_dir.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404)
        candidate = (static_dir / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = make_engine(settings.database_url, settings)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    @event.listens_for(session_factory, "after_commit")
    def _git_after_commit(session) -> None:
        if session.info.pop("git_dirty", False) and settings.git_enabled and settings.git_auto_sync:
            gitsync.request(session_factory, settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        check_secret_key(settings)
        if settings.auto_migrate:
            initialize(engine, session_factory, settings)
        scheduler = snapshot_jobs.Scheduler(
            session_factory, settings.snapshot_schedule, settings.default_verification_days
        )
        if settings.auto_migrate:
            scheduler.start()
        if settings.git_enabled:
            gitsync.request(session_factory, settings)
        poller = gitsync.Poller(session_factory, settings)
        poller.start()
        yield
        poller.stop()
        scheduler.stop()
        engine.dispose()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        # served below for signed-in users only
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    # JSON lists and the built bundle shrink 4 to 13 times; small answers are sent as they are
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        SecurityHeaders,
        hsts=settings.cookie_secure,
        max_body=settings.max_body_mb * 1024 * 1024,
        base_url=settings.base_url,
    )

    @app.exception_handler(IntegrityError)
    async def _conflict(_: Request, exc: IntegrityError) -> JSONResponse:
        # e.g. two users saving the same thing at the same moment: a clean 409, not a 500
        logging.getLogger("magma.db").info("Integrity error: %s", str(exc.orig)[:300])
        sqlstate = getattr(exc.orig, "sqlstate", None)
        unique = sqlstate == "23505" or "UNIQUE constraint" in str(exc.orig)
        if not unique:  # NOT NULL, foreign key ...: the request itself was wrong
            return JSONResponse(
                {"detail": "The data is incomplete or refers to something that does not exist."},
                status_code=422,
            )
        return JSONResponse(
            {"detail": "This was changed by someone else at the same time. Reload and retry."},
            status_code=409,
        )

    app.state.engine = engine
    app.state.login_limiter = FailureLimiter(
        settings.login_ip_max_failures, settings.login_ip_window_minutes * 60
    )
    app.state.sessionmaker = session_factory
    app.dependency_overrides[get_settings] = lambda: settings

    api = APIRouter(prefix="/api")
    docs_router = APIRouter(include_in_schema=False)

    @docs_router.get("/openapi.json")
    def openapi(_: Reader) -> JSONResponse:
        return JSONResponse(app.openapi())

    @docs_router.get("/docs")
    def docs(_: Reader) -> HTMLResponse:
        # Swagger UI from the installed package, not from a CDN: works in a closed network and
        # no third party script runs in the app's origin.
        return get_swagger_ui_html(
            openapi_url="/api/openapi.json",
            title=settings.app_name,
            swagger_js_url="/api/docs-assets/swagger-ui-bundle.js",
            swagger_css_url="/api/docs-assets/swagger-ui.css",
            swagger_favicon_url="/api/docs-assets/favicon-32x32.png",
        )

    @docs_router.get("/docs-assets/{name}")
    def docs_asset(name: str, _: Reader) -> FileResponse:
        if name not in DOCS_ASSETS:
            raise HTTPException(status_code=404)
        return FileResponse(Path(swagger_ui_path) / name)

    for r in (
        system,
        docs_router,
        auth.router,
        oidc.router,
        users.router,
        usecases.router,
        bulk.router,
        business.router,
        audit_log.router,
        scores.router,
        admin.router,
        configs.router,
        transfer.router,
        lifecycle.router,
        snapshots.router,
        gitsync_api.router,
        gitsync_api.hook,
        priorities.router,
        attack_api.router,
        output.router,
        integrations.router,
        app_settings.router,
        systems.router,
        evidence.router,
        purple.router,
        rounds.router,
        tasks.router,
        log_sources.router,
    ):
        api.include_router(r)
    app.include_router(api)
    _mount_frontend(app, settings.static_dir)
    return app


app = create_app()
