from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import User, require_admin
from ..db.models import ImageScan, Scan
from ..db.session import get_session
from ..logs import get_logger
from ..views import ACTIVE_SCAN_STATUSES, INTERNAL_RUNNING, page_params, scan_dict

log = get_logger(__name__)
router = APIRouter(tags=["scans"])
ENQUEUE_LOCK = 724_001


class ScanRequest(BaseModel):
    force: bool = False
    imageIds: list[int] | None = Field(default=None, max_length=1000)  # noqa: N815
    namespaces: list[str] | None = Field(default=None, max_length=500)


@router.get("/scans")
async def list_scans(page: int = 1, pageSize: int = Query(50), status: str | None = None,  # noqa: N803
                     session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    page, page_size = page_params(page, pageSize)
    stmt = select(Scan)
    if status:
        wanted = status.split(",")
        if "running" in wanted:
            wanted += list(INTERNAL_RUNNING)
        stmt = stmt.where(Scan.status.in_(wanted))
    rows = (await session.execute(stmt.order_by(Scan.id.desc()).offset((page - 1) * page_size).limit(page_size))).scalars()
    return [scan_dict(s) for s in rows]


@router.post("/scans", status_code=202)
async def create_scan(body: ScanRequest | None = None, user: User = Depends(require_admin),
                      session: AsyncSession = Depends(get_session)):
    body = body or ScanRequest()
    targeted = bool(body.imageIds)
    async with session.begin():
        await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ENQUEUE_LOCK})
        if not targeted:
            active = (await session.execute(
                select(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES), Scan.target_image_ids.is_(None))
                .order_by(Scan.id.desc()).limit(1)
            )).scalar_one_or_none()
            if active is not None:
                return JSONResponse({"detail": "a scan is already running", "scanId": active.id}, status_code=409)
        scan = Scan(trigger="manual", status="queued", requested_by=user.username, force=body.force,
                    target_image_ids=body.imageIds or None, target_namespaces=body.namespaces or None,
                    per_scanner={}, log=[])
        session.add(scan)
        await session.flush()
        await session.refresh(scan)
        out = scan_dict(scan)
    log.info("scan.requested", scan_id=out["id"], user=user.username, targeted=targeted, force=body.force)
    return out


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, detail="scan not found")
    out = scan_dict(scan)
    per: dict[str, dict[str, Any]] = {k: {"ok": v.get("ok", 0), "error": v.get("error", 0)}
                                      for k, v in (scan.per_scanner or {}).items()}
    # authoritative counts from image_scans when available
    rows = (await session.execute(
        select(ImageScan.scanner, ImageScan.status, func.count()).where(ImageScan.scan_id == scan_id)
        .group_by(ImageScan.scanner, ImageScan.status)
    )).all()
    if rows:
        per = {}
        for scanner, status, n in rows:
            b = per.setdefault(scanner, {"ok": 0, "error": 0})
            b["ok" if status == "ok" else "error"] += n
    out["perScanner"] = per
    out["log"] = list(scan.log or [])[-200:]
    out["progress"] = round(scan.images_done / scan.images_total, 4) if scan.images_total else (
        1.0 if scan.status == "done" else 0.0)
    return out


@router.delete("/scans/{scan_id}")
async def cancel_scan(scan_id: int, user: User = Depends(require_admin),
                      session: AsyncSession = Depends(get_session)):
    async with session.begin():
        scan = await session.get(Scan, scan_id, with_for_update=True)
        if scan is None:
            raise HTTPException(404, detail="scan not found")
        if scan.status not in ACTIVE_SCAN_STATUSES:
            return JSONResponse({"detail": f"scan is already {scan.status}"}, status_code=409)
        if scan.status == "queued":
            from datetime import UTC, datetime

            scan.finished_at = datetime.now(UTC)
        scan.status = "cancelled"
        scan.log = [*(scan.log or []), f"cancel requested by {user.username}"][-200:]
        await session.flush()
        out = scan_dict(scan)
    log.info("scan.cancel_requested", scan_id=scan_id, user=user.username)
    return out
