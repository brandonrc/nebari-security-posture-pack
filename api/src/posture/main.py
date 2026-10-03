"""FastAPI application: `uvicorn posture.main:app` (DESIGN §5)."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse

from . import __version__
from .auth import current_user, get_authenticator, require_admin
from .config import get_settings
from . import report_jobs
from .db.session import dispose_engine, get_sessionmaker
from .logs import get_logger, setup_logging
from .routers import (
    checks,
    compliance,
    controls,
    export,
    health,
    images,
    me,
    provenance_compat,
    reports,
    scanners,
    scans,
    settings,
    summary,
    supply_chain,
    vulnerabilities,
    workloads,
)

PREFIX = "/api/v1"
log = get_logger("posture.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    setup_logging(s.log_level)
    get_authenticator()  # logs a warning when AUTH_MODE=disabled
    log.info("api.start", version=__version__, auth_mode=s.auth_mode, reports_dir=s.reports_dir)
    try:
        await report_jobs.fail_interrupted(get_sessionmaker())
    except Exception as e:  # noqa: BLE001  (DB may still be migrating; not fatal)
        log.warning("api.reports_recover_failed", error=str(e))
    internal = await provenance_compat.start_internal(s)  # DESIGN §12 Grafana listener (opt-in)
    yield
    if internal is not None:
        await internal.stop()
    await dispose_engine()


def create_app() -> FastAPI:
    setup_logging(get_settings().log_level)
    app = FastAPI(
        title="Nebari Security Posture API",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("http.unhandled", method=request.method, path=request.url.path)
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        path = request.url.path
        if not path.endswith(("/health", "/ready")):
            log.info("http.request", method=request.method, path=path, status=response.status_code,
                     duration_ms=int((time.monotonic() - start) * 1000))
        return response

    public = APIRouter(prefix=PREFIX)
    public.include_router(health.router)
    app.include_router(public)
    app.include_router(health.router)  # unprefixed /health, /ready for probes

    authed = APIRouter(prefix=PREFIX, dependencies=[Depends(current_user)])
    authed.include_router(me.router)
    app.include_router(authed)

    admin = APIRouter(prefix=PREFIX, dependencies=[Depends(require_admin)])
    for r in (summary.router, images.router, vulnerabilities.router, workloads.router, workloads.ns_router,
              checks.router, scans.router, scanners.router, settings.router, export.router, compliance.router,
              reports.router, supply_chain.router):
        admin.include_router(r)

    admin.include_router(controls.router)  # DESIGN §13 control evidence engine (/compliance/controls, ...)

    @admin.get("/openapi.json", include_in_schema=False)
    async def openapi_json():
        return JSONResponse(app.openapi())

    @admin.get("/docs", include_in_schema=False)
    async def swagger():
        return get_swagger_ui_html(openapi_url=f"{PREFIX}/openapi.json", title="Security Posture API")

    app.include_router(admin)
    provenance_compat.include(app)  # provenance-collector-pack API aliases outside /api/v1 (DESIGN §12)
    app.state.admin_router = admin  # reports agent can mount additional routers here
    return app


app = create_app()
