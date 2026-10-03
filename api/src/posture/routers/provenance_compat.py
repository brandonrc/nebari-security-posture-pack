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
serves ONLY the read endpoints (`/api/reports*`, `/api/export`, `/healthz`) for Grafana
Infinity through the ClusterIP Service `<fullname>-web-internal` (chart
`provenance.compat.internalService`). It is never routed by the gateway. Security review H2:
the read endpoints require `Authorization: Bearer <token>` where the token is read from
`PROVENANCE_COMPAT_TOKEN_FILE` (a mounted Secret; re-read when the file changes) or
`PROVENANCE_COMPAT_TOKEN`; Grafana's datasource sends it as a header. Without a token the
listener refuses to start unless `PROVENANCE_COMPAT_ALLOW_ANONYMOUS=true` (the old,
unauthenticated behaviour of their `-web` Service). `/healthz` stays open for probes.

The report list and the latest report are cached in-process and invalidated when a newer
scan appears (each scan's summary is built at most once; the list is capped at 50).
"""

from __future__ import annotations

import asyncio
import json
import hmac
import os
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..auth import User, get_authenticator, require_admin
from ..config import Settings
from ..db.session import get_session
from ..logs import get_logger
from sqlalchemy import select

from ..db.models import CompatReportRow, Scan
from ..provenance.models import ImageProvenance
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


LIST_LIMIT = 50


class ReportCache:
    """In-process cache (security review H2 DoS): per-scan list entries (a scan's report never
    changes once it is done), the rendered list bytes and the latest report bytes, keyed by the
    newest report scan id + cluster name so a new scan invalidates them."""

    def __init__(self, max_entries: int = LIST_LIMIT * 2):
        self.max_entries = max_entries
        self.entries: OrderedDict[tuple[int, str], dict[str, Any]] = OrderedDict()
        self.list_key: tuple[Any, ...] | None = None
        self.list_bytes: bytes | None = None
        self.latest_key: tuple[int, str] | None = None
        self.latest_bytes: bytes | None = None
        self.lock = asyncio.Lock()

    def clear(self) -> None:
        self.entries.clear()
        self.list_key = self.list_bytes = self.latest_key = self.latest_bytes = None


CACHE = ReportCache()


async def _latest_report_scan_ids(session: AsyncSession, limit: int = LIST_LIMIT) -> list[int]:
    ids = select(ImageProvenance.scan_id).distinct()
    return list((await session.execute(
        select(Scan.id).where(Scan.status == "done", Scan.inventory_complete.is_(True), Scan.id.in_(ids))
        .order_by(Scan.id.desc()).limit(limit))).scalars())


async def _get_scan(session: AsyncSession, scan_id: int) -> Scan | None:
    return await session.get(Scan, scan_id)


async def _stored(session: AsyncSession, scan_id: int, name: str) -> CompatReportRow | None:
    """The report the worker materialized for this scan (architecture review §1), if it was
    rendered for the current cluster name."""
    if session is None:  # unit tests drive the handlers without a database
        return None
    row = await session.get(CompatReportRow, scan_id)
    if row is None or (row.cluster_name or "") != (name or ""):
        return None
    return row


async def _entry(session: AsyncSession, scan: Scan, name: str) -> dict[str, Any]:
    key = (scan.id, name)
    hit = CACHE.entries.get(key)
    if hit is not None:
        CACHE.entries.move_to_end(key)
        return hit
    stored = await _stored(session, scan.id, name)
    if stored is not None:
        entry = {"filename": stored.filename, "generatedAt": stored.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "summary": stored.summary}
        if stored.cluster_name:
            entry["clusterName"] = stored.cluster_name
        CACHE.entries[key] = entry
        return entry
    doc = await load_report(session, scan, name)
    entry: dict[str, Any] = {"filename": report_filename(scan_time(scan)),
                             "generatedAt": scan_time(scan).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             "summary": doc["summary"]}
    if doc["metadata"].get("clusterName"):
        entry["clusterName"] = doc["metadata"]["clusterName"]
    CACHE.entries[key] = entry
    while len(CACHE.entries) > CACHE.max_entries:
        CACHE.entries.popitem(last=False)
    return entry


async def list_reports(session: AsyncSession) -> Response:
    name = await _cluster_name(session)
    ids = await _latest_report_scan_ids(session)
    key = (tuple(ids), name)
    async with CACHE.lock:
        if CACHE.list_key != key or CACHE.list_bytes is None:
            scans = {s.id: s for s in await report_scans(session, limit=LIST_LIMIT)}
            entries = [await _entry(session, scans[i], name) for i in ids if i in scans]
            entries.sort(key=lambda e: e["generatedAt"], reverse=True)
            CACHE.list_bytes = go_json(entries, indent=False)
            CACHE.list_key = key
        body = CACHE.list_bytes
    return Response(body, media_type="application/json")


async def get_report(filename: str, session: AsyncSession) -> Response:
    if _invalid(filename):
        return _text_error("invalid filename", 400)
    name = await _cluster_name(session)
    if filename in ("latest", LATEST_FILENAME):
        ids = await _latest_report_scan_ids(session, limit=1)
        if not ids:
            return _text_error("report not found", 404)
        key = (ids[0], name)
        async with CACHE.lock:
            if CACHE.latest_key != key or CACHE.latest_bytes is None:
                stored = await _stored(session, ids[0], name)
                scan = await _get_scan(session, ids[0])
                if scan is None:
                    return _text_error("report not found", 404)
                CACHE.latest_bytes = stored.body if stored is not None else go_json(
                    await load_report(session, scan, name), indent=True)
                CACHE.latest_key = key
            body = CACHE.latest_bytes
        return Response(body, media_type="application/json")
    scan = await find_scan(session, filename)
    if scan is None:
        return _text_error("report not found", 404)
    stored = await _stored(session, scan.id, name)
    if stored is not None:
        return Response(stored.body, media_type="application/json")
    return _json(await load_report(session, scan, name), indent=True)


async def export(format: str | None, filename: str | None, session: AsyncSession) -> Response:  # noqa: A002
    fmt = format or "csv"
    name = filename or LATEST_FILENAME
    if filename and _invalid(filename):
        return _text_error("invalid filename", 400)
    scan = await find_scan(session, name)
    if scan is None:
        return _text_error("report not found", 404)
    cluster = await _cluster_name(session)
    stored = await _stored(session, scan.id, cluster)
    doc = json.loads(stored.body) if stored is not None else await load_report(session, scan, cluster)
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


class CompatConfigError(RuntimeError):
    pass


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


class InternalToken:
    """Static bearer token for the internal listener: PROVENANCE_COMPAT_TOKEN_FILE (re-read when
    its mtime changes, so a rotated Secret is picked up) or PROVENANCE_COMPAT_TOKEN."""

    def __init__(self, path: str | None = None, value: str | None = None, allow_anonymous: bool = False):
        self.path = path or None
        self.value = (value or "").strip()
        self.allow_anonymous = allow_anonymous
        self._mtime: float | None = None
        self._file_value = ""

    @classmethod
    def from_env(cls) -> InternalToken:
        return cls(os.environ.get("PROVENANCE_COMPAT_TOKEN_FILE"), os.environ.get("PROVENANCE_COMPAT_TOKEN"),
                   _truthy(os.environ.get("PROVENANCE_COMPAT_ALLOW_ANONYMOUS")))

    def current(self) -> str:
        if self.path:
            try:
                mtime = os.stat(self.path).st_mtime
                if mtime != self._mtime:
                    with open(self.path, encoding="utf-8") as fh:
                        self._file_value = fh.read().strip()
                    self._mtime = mtime
            except OSError as e:
                log.warning("provenance.compat_token_unreadable", path=self.path, error=type(e).__name__)
                self._file_value, self._mtime = "", None
            return self._file_value
        return self.value

    def check_config(self) -> None:
        if not self.current() and not self.allow_anonymous:
            raise CompatConfigError(
                "PROVENANCE_COMPAT_INTERNAL_PORT is set but no PROVENANCE_COMPAT_TOKEN_FILE / PROVENANCE_COMPAT_TOKEN "
                "(or an empty one); set PROVENANCE_COMPAT_ALLOW_ANONYMOUS=true to serve it without auth")
        if not self.current():
            log.warning("provenance.compat_internal_anonymous",
                        detail="PROVENANCE_COMPAT_ALLOW_ANONYMOUS=true: inventory readable by any in-cluster caller")

    def dependency(self) -> Callable[[Request], Any]:
        async def require_token(request: Request) -> None:
            expected = self.current()
            if not expected:
                if self.allow_anonymous:
                    return
                raise HTTPException(503, detail="internal listener token not configured")
            authz = request.headers.get("authorization") or ""
            given = authz[7:].strip() if authz.lower().startswith("bearer ") else ""
            if not given or not hmac.compare_digest(given.encode(), expected.encode()):
                raise HTTPException(401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})

        return require_token


def internal_app(token: InternalToken | None = None) -> FastAPI:
    """Read-only app for the `-web-internal` Service (Grafana), bearer-token protected."""
    token = token or InternalToken.from_env()
    app = FastAPI(title="provenance-compat (internal)", docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(make_public_router())
    app.include_router(make_read_router([Depends(token.dependency())]))
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
    InternalToken.from_env().check_config()  # refuse to start an unauthenticated listener by accident
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app_factory(), host="0.0.0.0", port=int(port), log_config=None,
                                           access_log=False, lifespan="off"))
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    task = asyncio.create_task(server.serve())
    log.info("provenance.compat_internal_listening", port=port)
    return InternalServer(server, task)
