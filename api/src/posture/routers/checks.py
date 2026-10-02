from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import PostureResultRow
from ..db.session import get_session
from ..posture_checks import CHECKS, CHECKS_BY_ID, CheckDef
from ..views import latest_done_scan

router = APIRouter(tags=["checks"])


def check_dict(c: CheckDef, passed: int = 0, failed: int = 0) -> dict[str, Any]:
    return {"id": c.id, "title": c.title, "severity": c.severity, "category": c.category, "scope": c.scope,
            "description": c.description, "remediation": c.remediation, "controls": c.controls,
            "passed": passed, "failed": failed}


async def check_counts(session: AsyncSession) -> dict[str, dict[str, int]]:
    latest = await latest_done_scan(session)
    out: dict[str, dict[str, int]] = {}
    if latest is None:
        return out
    for cid, status, n in (await session.execute(
        select(PostureResultRow.check_id, PostureResultRow.status, func.count())
        .where(PostureResultRow.scan_id == latest.id).group_by(PostureResultRow.check_id, PostureResultRow.status)
    )).all():
        out.setdefault(cid, {"pass": 0, "fail": 0})[status] = n
    return out


@router.get("/checks")
async def list_checks(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    counts = await check_counts(session)
    return [check_dict(c, counts.get(c.id, {}).get("pass", 0), counts.get(c.id, {}).get("fail", 0)) for c in CHECKS]


@router.get("/checks/{check_id}")
async def get_check(check_id: str, status: str | None = None, namespace: str | None = None,
                    session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    c = CHECKS_BY_ID.get(check_id)
    if c is None:
        raise HTTPException(404, detail="check not found")
    counts = (await check_counts(session)).get(check_id, {})
    out = check_dict(c, counts.get("pass", 0), counts.get("fail", 0))
    latest = await latest_done_scan(session)
    results: list[dict[str, Any]] = []
    if latest:
        stmt = select(PostureResultRow).where(PostureResultRow.scan_id == latest.id,
                                              PostureResultRow.check_id == check_id)
        if status:
            stmt = stmt.where(PostureResultRow.status == status)
        if namespace:
            stmt = stmt.where(PostureResultRow.namespace.in_(namespace.split(",")))
        rows = (await session.execute(stmt.order_by(PostureResultRow.status, PostureResultRow.namespace,
                                                    PostureResultRow.name))).scalars().all()
        results = [{"namespace": r.namespace, "kind": r.kind, "name": r.name, "container": r.container,
                    "pod": r.pod, "status": r.status, "detail": r.detail, "severity": r.severity,
                    "weight": r.weight, "systemNamespace": r.system_namespace} for r in rows]
        results.sort(key=lambda r: r["status"] != "fail")
    out["results"] = results
    return out
