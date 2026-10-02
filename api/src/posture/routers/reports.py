"""Compliance reports (DESIGN §11): `/reports*` and `GET /compliance/stig`."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import report_jobs
from ..auth import User, require_admin
from ..db.models import Report, Scan
from ..db.session import get_session, get_sessionmaker
from ..logs import get_logger
from ..reports import registry
from ..reports.registry import ReportDependencyMissing, UnsupportedReport
from ..reports.snapshot import build_snapshot
from ..reports.stig import stig_rollup
from ..views import latest_done_scan

log = get_logger(__name__)
router = APIRouter(tags=["reports"])


class ScopeIn(BaseModel):
    kind: str = "cluster"
    name: str | None = Field(default=None, max_length=512)


class ReportRequest(BaseModel):
    type: str = Field(max_length=32)
    format: str | None = Field(default=None, max_length=16)
    scope: ScopeIn | None = None
    scanId: int | None = None  # noqa: N815
    options: dict[str, Any] | None = None


def _pdf_available() -> None:
    """Fail fast (503) when WeasyPrint's system libraries are missing."""
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError) as exc:
        raise ReportDependencyMissing(f"PDF rendering unavailable: {str(exc).splitlines()[0]}") from exc


def _uuid(report_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(404, detail="report not found") from None


@router.get("/reports/types")
async def report_types() -> list[dict[str, Any]]:
    return [{**t, "defaultFormat": report_jobs.DEFAULT_FORMATS.get(t["type"], t["formats"][0])}
            for t in registry.REPORT_TYPES]


@router.get("/reports")
async def list_reports(scanId: int | None = None, type: str | None = None,  # noqa: A002,N803
                       session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    stmt = select(Report)
    if scanId is not None:
        stmt = stmt.where(Report.scan_id == scanId)
    if type:
        stmt = stmt.where(Report.type.in_(type.split(",")))
    rows = (await session.execute(stmt.order_by(Report.created_at.desc()).limit(500))).scalars().all()
    return [report_jobs.report_dict(r) for r in rows]


@router.post("/reports", status_code=202)
async def create_report(body: ReportRequest, background: BackgroundTasks, user: User = Depends(require_admin),
                        session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    scope = body.scope.model_dump() if body.scope else None
    try:
        fmt, kind, name = report_jobs.validate_request(body.type, body.format, scope, body.options)
        if fmt == "pdf":
            _pdf_available()
    except UnsupportedReport as e:
        raise HTTPException(422, detail=str(e)) from e
    except ReportDependencyMissing as e:
        raise HTTPException(503, detail=str(e)) from e
    async with session.begin():
        if body.scanId is not None:
            scan = await session.get(Scan, body.scanId)
            if scan is None:
                raise HTTPException(404, detail="scan not found")
            if scan.status != "done":
                raise HTTPException(409, detail=f"scan {scan.id} is {scan.status}, not done")
        else:
            scan = await latest_done_scan(session)
            if scan is None:
                raise HTTPException(409, detail="no completed scan yet")
        row = await report_jobs.create_row(session, report_type=body.type, fmt=fmt, scope_kind=kind,
                                           scope_name=name, scan_id=scan.id, options=body.options,
                                           created_by=user.username)
        out = report_jobs.report_dict(row)
    background.add_task(report_jobs.run_report, get_sessionmaker(), row.id)
    log.info("report.requested", report_id=out["id"], type=body.type, format=fmt, scope=kind, user=user.username)
    return out


@router.get("/reports/{report_id}")
async def get_report(report_id: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    row = await session.get(Report, _uuid(report_id))
    if row is None:
        raise HTTPException(404, detail="report not found")
    return report_jobs.report_dict(row)


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str, session: AsyncSession = Depends(get_session)):
    row = await session.get(Report, _uuid(report_id))
    if row is None:
        raise HTTPException(404, detail="report not found")
    if row.status != "done" or not row.path:
        raise HTTPException(409, detail=f"report is {row.status}")
    path = Path(row.path)
    if not await asyncio.to_thread(path.is_file):
        raise HTTPException(410, detail="report file is missing (storage was reset); generate it again")
    return FileResponse(path, media_type=row.content_type or "application/octet-stream",
                        filename=row.filename or path.name, content_disposition_type="attachment",
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.delete("/reports/{report_id}", status_code=204)
async def delete_report(report_id: str, session: AsyncSession = Depends(get_session)) -> Response:
    rid = _uuid(report_id)
    async with session.begin():
        row = await session.get(Report, rid, with_for_update=True)
        if row is None:
            raise HTTPException(404, detail="report not found")
        path = row.path or str(report_jobs.reports_dir() / f"{rid}.{row.format}")
        await session.delete(row)
    await asyncio.to_thread(report_jobs.delete_file, path)
    return Response(status_code=204)


@router.get("/compliance/stig")
async def compliance_stig(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    latest = await latest_done_scan(session)
    if latest is None:
        return []
    snapshot = await build_snapshot(session, latest.id, None)
    rules = await asyncio.to_thread(stig_rollup, snapshot, None)
    for r in rules:
        r["checkId"] = (r.get("checks") or [None])[0]
    return rules
