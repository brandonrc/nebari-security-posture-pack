"""provenance-collector-pack drop-in API (DESIGN §12), mounted OUTSIDE `/api/v1`.

| theirs | here |
|---|---|
| `GET /api/reports` | completed scans with provenance results, newest first: `[{filename, generatedAt, summary, clusterName?}]` |
| `GET /api/reports/latest`, `/api/reports/provenance-latest.json`, `/api/reports/{filename}` | report JSON (their schema, Go-identical serialization) |
| `GET /api/export?format=csv|markdown|md|json&filename=` | their CSV / Markdown (json = the report) |
| `GET /api/me` | `{authEnabled, email?, groups?, canRunScan, features}` |
| `POST /api/scan` | enqueues one of our scans -> `{jobName, namespace}` (409 when one is active) |
| `GET /healthz` | `{"status":"ok"}` |

Auth on the main listener is the same as the rest of the API (admin group), except
`/healthz` (public) and `/api/me` (answers for anonymous callers, like theirs).

`PROVENANCE_COMPAT_INTERNAL_PORT` starts a second listener in the api process that
serves ONLY the read endpoints (`/api/reports*`, `/api/export`, `/healthz`) WITHOUT auth,
for Grafana Infinity through the ClusterIP Service `<fullname>-web-internal` (chart
`provenance.compat.internalService`) - the equivalent of their unauthenticated
in-cluster `-web` Service. It is never routed by the gateway; a NetworkPolicy limits
who may reach it.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..auth import User, get_authenticator, require_admin
from ..config import Settings
from ..db.session import get_session
from ..logs import get_logger
from ..provenance.report import (
    LATEST_FILENAME,
    export_csv,
    export_markdown,
    find_scan,
    go_json,
    load_report,
    report_filename,
    report_scans,
    scan_time,
)

log = get_logger(__name__)
SA_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def _text_error(msg: str, status: int) -> PlainTextResponse:
    """Go `http.Error`: text/plain body with a trailing newline."""
    return PlainTextResponse(msg + "\n", status_code=status, headers={"X-Content-Type-Options": "nosniff"})


def _json(data: Any, indent: bool) -> Response:
    return Response(go_json(data, indent=indent), media_type="application/json")


def _invalid(filename: str) -> bool:
    return not filename or "/" in filename or ".." in filename


async def _cluster_name(session: AsyncSession) -> str:
    return (await app_settings.load(session)).system_name


async def list_reports(session: AsyncSession) -> Response:
    name = await _cluster_name(session)
    entries = []
    for scan in await report_scans(session):
        doc = await load_report(session, scan, name)
        entry: dict[str, Any] = {"filename": report_filename(scan_time(scan)),
                                 "generatedAt": scan_time(scan).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "summary": doc["summary"]}
        if doc["metadata"].get("clusterName"):
            entry["clusterName"] = doc["metadata"]["clusterName"]
        entries.append(entry)
    entries.sort(key=lambda e: e["generatedAt"], reverse=True)
    return _json(entries, indent=False)


async def get_report(filename: str, session: AsyncSession) -> Response:
    if _invalid(filename):
        return _text_error("invalid filename", 400)
    scan = await find_scan(session, filename)
    if scan is None:
        return _text_error("report not found", 404)
    return _json(await load_report(session, scan, await _cluster_name(session)), indent=True)


async def export(format: str | None, filename: str | None, session: AsyncSession) -> Response:  # noqa: A002
    fmt = format or "csv"
    name = filename or LATEST_FILENAME
    if filename and _invalid(filename):
        return _text_error("invalid filename", 400)
    scan = await find_scan(session, name)
    if scan is None:
        return _text_error("report not found", 404)
    doc = await load_report(session, scan, await _cluster_name(session))
    if fmt == "csv":
        return Response(export_csv(doc), headers={"Content-Type": "text/csv",  # no charset, like theirs
                                                  "Content-Disposition": "attachment; filename=provenance-report.csv"})
    if fmt in ("markdown", "md"):
        return Response(export_markdown(doc), headers={"Content-Type": "text/markdown",
                                                       "Content-Disposition": "attachment; filename=provenance-report.md"})
    if fmt == "json":
        return Response(go_json(doc), media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=provenance-report.json"})
    return _text_error("unsupported format: use csv or markdown", 400)


def make_read_router(dependencies: list | None = None) -> APIRouter:
    r = APIRouter(dependencies=dependencies or [], tags=["provenance-compat"])

    @r.get("/api/reports")
    async def _list(session: AsyncSession = Depends(get_session)) -> Response:
        return await list_reports(session)

    @r.get("/api/reports/{filename}")
    async def _get(filename: str, session: AsyncSession = Depends(get_session)) -> Response:
        return await get_report(filename, session)

    @r.get("/api/export")
    async def _export(format: str | None = None, filename: str | None = None,  # noqa: A002
                      session: AsyncSession = Depends(get_session)) -> Response:
        return await export(format, filename, session)

    return r


def make_public_router() -> APIRouter:
    r = APIRouter(tags=["provenance-compat"])

    @r.get("/healthz")
    async def healthz() -> Response:
        return Response(b'{"status":"ok"}', media_type="application/json")

    return r


def _namespace() -> str:
    try:
        with open(SA_NAMESPACE_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return os.environ.get("POD_NAMESPACE", "")


def make_session_router() -> APIRouter:
    """`/api/me` and `POST /api/scan` (main listener only)."""
    r = APIRouter(tags=["provenance-compat"])

    @r.get("/api/me")
    async def me(request: Request) -> Response:
        auth = get_authenticator()
        user: User | None = None
        try:
            user = await auth.authenticate(request)
        except Exception:  # noqa: BLE001  (anonymous is a valid answer here)
            user = None
        body: dict[str, Any] = {"authEnabled": not auth.settings.auth_disabled}
        if user is not None and user.email:
            body["email"] = user.email
        if user is not None and user.groups:
            body["groups"] = user.groups
        body["canRunScan"] = bool(user and user.is_admin)
        body["features"] = {"timelineDeltas": True}
        return _json(body, indent=False)

    @r.post("/api/scan")
    async def scan(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
        # their CSRF defence: browsers always send Sec-Fetch-Site; fail closed without it
        if request.headers.get("sec-fetch-site") != "same-origin":
            return _text_error("cross-origin requests not allowed", 403)
        try:
            user = await get_authenticator().authenticate(request)
        except Exception:  # noqa: BLE001
            user = None
        if user is None or not user.is_admin:
            return _text_error("forbidden: caller is not in an admin group", 403)
        from .scans import ScanRequest, create_scan

        result = await create_scan(ScanRequest(), user, session)
        if isinstance(result, JSONResponse):
            return _text_error("a scan job is already active for this collector", 409)
        return _json({"jobName": f"posture-scan-{result['id']}", "namespace": _namespace(), "scanId": result["id"]},
                     indent=False)

    return r


def include(app: FastAPI) -> None:
    """Mount on the main app (outside /api/v1): admin-gated reads, /api/me, /api/scan, /healthz."""
    app.include_router(make_public_router())
    app.include_router(make_session_router())
    app.include_router(make_read_router([Depends(require_admin)]))


def internal_app() -> FastAPI:
    """Unauthenticated read-only app for the `-web-internal` Service (Grafana)."""
    app = FastAPI(title="provenance-compat (internal)", docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(make_public_router())
    app.include_router(make_read_router())
    return app


class InternalServer:
    def __init__(self, server: Any, task: asyncio.Task):
        self.server, self.task = server, task

    async def stop(self) -> None:
        self.server.should_exit = True
        try:
            await asyncio.wait_for(self.task, 10)
        except (TimeoutError, asyncio.TimeoutError, asyncio.CancelledError):
            self.task.cancel()


async def start_internal(settings: Settings, app_factory: Callable[[], FastAPI] = internal_app) -> InternalServer | None:
    """Second listener on PROVENANCE_COMPAT_INTERNAL_PORT, same event loop (shares the DB engine)."""
    port = settings.provenance_compat_internal_port
    if not port:
        return None
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app_factory(), host="0.0.0.0", port=int(port), log_config=None,
                                           access_log=False, lifespan="off"))
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    task = asyncio.create_task(server.serve())
    log.info("provenance.compat_internal_listening", port=port)
    return InternalServer(server, task)
