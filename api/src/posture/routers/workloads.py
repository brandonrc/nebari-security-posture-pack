from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Image, ScanSnapshot, WorkloadRow
from ..db.session import get_session
from ..views import counts_of, latest_done_scan

router = APIRouter(tags=["workloads"])


@router.get("/workloads")
async def list_workloads(namespace: str | None = None, kind: str | None = None, q: str | None = None,
                         session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    latest = await latest_done_scan(session)
    if latest is None:
        return []
    stmt = select(WorkloadRow).where(WorkloadRow.scan_id == latest.id)
    if namespace:
        stmt = stmt.where(WorkloadRow.namespace.in_(namespace.split(",")))
    if kind:
        stmt = stmt.where(WorkloadRow.kind.in_(kind.split(",")))
    rows = (await session.execute(stmt.order_by(WorkloadRow.namespace, WorkloadRow.kind, WorkloadRow.name))).scalars().all()
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r.name.lower() or ql in r.namespace.lower() or ql in (r.pack or "").lower()]
    ids = {i for r in rows for i in (r.image_ids or [])}
    refs = {i.id: i.ref for i in (await session.execute(select(Image).where(Image.id.in_(ids or {0})))).scalars()}
    return [{
        "namespace": r.namespace, "kind": r.kind, "name": r.name, "pack": r.pack, "score": r.score,
        "grade": r.grade, "vulnScore": r.vuln_score, "postureScore": r.posture_score,
        "images": [{"imageId": i, "ref": refs.get(i)} for i in (r.image_ids or [])],
        "containers": r.containers, "runningContainers": r.running_containers,
        "posture": {"passed": r.posture_passed, "failed": r.posture_failed},
        "counts": counts_of(r.counts), "systemNamespace": r.system_namespace,
    } for r in rows]


async def namespace_rows(session: AsyncSession) -> list[dict[str, Any]]:
    latest = await latest_done_scan(session)
    if latest is None:
        return []
    snaps = (await session.execute(
        select(ScanSnapshot).where(ScanSnapshot.scan_id == latest.id, ScanSnapshot.level == "namespace")
        .order_by(ScanSnapshot.key)
    )).scalars().all()
    out = []
    for s in snaps:
        d = s.data or {}
        out.append({
            "name": s.key, "pack": d.get("pack"), "managed": bool(d.get("managed")), "score": s.score,
            "grade": s.grade or "?", "workloads": d.get("workloads", 0), "images": d.get("images", 0),
            "counts": counts_of(d.get("counts")), "posture": d.get("posture") or {"passed": 0, "failed": 0},
            "containers": d.get("containers", 0), "runningContainers": d.get("runningContainers", 0),
        })
    return out


ns_router = APIRouter(tags=["namespaces"])


@ns_router.get("/namespaces")
async def list_namespaces(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    return await namespace_rows(session)
