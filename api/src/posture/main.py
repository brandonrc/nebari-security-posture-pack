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
from .db.session import dispose_engine
from .logs import get_logger, setup_logging
from .routers import (
    checks,
    compliance,
    export,
    health,
    images,
    me,
    scanners,
    scans,
    settings,
    summary,
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
    log.info("api.start", version=__version__, auth_mode=s.auth_mode)
    yield
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
              checks.router, scans.router, scanners.router, settings.router, export.router, compliance.router):
        admin.include_router(r)

    @admin.get("/openapi.json", include_in_schema=False)
    async def openapi_json():
        return JSONResponse(app.openapi())

    @admin.get("/docs", include_in_schema=False)
    async def swagger():
        return get_swagger_ui_html(openapi_url=f"{PREFIX}/openapi.json", title="Security Posture API")

    app.include_router(admin)
    app.state.admin_router = admin  # reports agent can mount additional routers here
    return app


app = create_app()
