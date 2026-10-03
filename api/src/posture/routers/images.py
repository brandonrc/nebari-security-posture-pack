from __future__ import annotations

import gzip
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..db.models import ConsensusFindingRow, ContainerRow, Image, ImageScan, PostureResultRow
from ..db.session import get_session
from ..posture_checks import CHECKS_BY_ID
from ..severity import SEVERITIES, severity_rank
from ..views import (
    container_ref,
    counts_of,
    current_image_ids,
    finding_dict,
    image_scan_dict,
    image_summary,
    latest_done_scan,
    page_params,
)

router = APIRouter(tags=["images"])

SORT_KEYS = {
    "score": lambda d: (d["score"] is None, d["score"] if d["score"] is not None else 0),
    "ref": lambda d: d["ref"].lower(),
    "grade": lambda d: d["grade"],
    "critical": lambda d: d["counts"]["critical"],
    "high": lambda d: d["counts"]["high"],
    "findings": lambda d: sum(d["counts"].values()),
    "lastScannedAt": lambda d: d["lastScannedAt"] or "",
    "containers": lambda d: d["containers"],
    "workloads": lambda d: d["workloads"],
    "agreementIndex": lambda d: d["agreementIndex"] if d["agreementIndex"] is not None else -1,
}


def filter_images(items: list[dict[str, Any]], namespace: str | None, grade: str | None, severity: str | None,
                  q: str | None, running: bool | None, current: bool | None = None) -> list[dict[str, Any]]:
    out = items
    if namespace:
        nss = set(namespace.split(","))
        out = [d for d in out if nss & set(d["namespaces"])]
    if grade:
        grades = {g.strip().upper() for g in grade.split(",")}
        out = [d for d in out if d["grade"] in grades]
    if severity:
        sevs = [s.strip().lower() for s in severity.split(",") if s.strip().lower() in SEVERITIES]
        out = [d for d in out if any(d["counts"][s] > 0 for s in sevs)]
    if q:
        ql = q.lower()
        out = [d for d in out if ql in d["ref"].lower() or ql in (d["digest"] or "").lower()]
    if running is not None:
        out = [d for d in out if d["running"] == running]
    if current is not None:
        out = [d for d in out if (d.get("current") is not False) == current]
    return out


@router.get("/images")
async def list_images(
    namespace: str | None = None,
    grade: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    running: bool | None = None,
    current: bool | None = None,
    sort: str = "score",
    order: str | None = None,
    page: int = 1,
    pageSize: int = Query(50, alias="pageSize"),  # noqa: N803
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    page, page_size = page_params(page, pageSize)
    imgs = (await session.execute(select(Image))).scalars().all()
    cur = await current_image_ids(session)
    items = [image_summary(i) for i in imgs]
    for d in items:  # in the latest done scan's inventory (False = stale); None before any scan
        d["current"] = None if cur is None else d["id"] in cur
    items = filter_images(items, namespace, grade, severity, q, running, current)
    keyfn = SORT_KEYS.get(sort, SORT_KEYS["score"])
    default_desc = sort not in ("score", "ref", "grade")
    desc = (order or ("desc" if default_desc else "asc")).lower() == "desc"
    items.sort(key=keyfn, reverse=desc)
    if sort == "score":  # unscored images always last
        items.sort(key=lambda d: d["score"] is None)
    total = len(items)
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total, "page": page, "pageSize": page_size}


async def _image_or_404(session: AsyncSession, image_id: int) -> Image:
    img = await session.get(Image, image_id)
    if img is None:
        raise HTTPException(404, detail="image not found")
    return img


@router.get("/images/{image_id}")
async def get_image(image_id: int, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    img = await _image_or_404(session, image_id)
    settings = await app_settings.load(session)
    sla = settings.remediation_sla_days.model_dump()
    findings = (await session.execute(
        select(ConsensusFindingRow).where(ConsensusFindingRow.image_id == image_id)
    )).scalars().all()
    fl = sorted((finding_dict(f, sla) for f in findings),
                key=lambda f: (-severity_rank(f["severity"]), -(f["cvss"] or 0), f["vulnId"]))
    latest = await latest_done_scan(session)
    used_by: list[dict[str, Any]] = []
    posture: list[dict[str, Any]] = []
    if latest:
        conts = (await session.execute(
            select(ContainerRow).where(ContainerRow.scan_id == latest.id, ContainerRow.image_fk == image_id)
        )).scalars().all()
        used_by = [container_ref(c) for c in conts]
        keys = {(c.namespace, c.workload_kind, c.workload_name) for c in conts}
        cnames = {(c.namespace, c.workload_kind, c.workload_name, c.container) for c in conts}
        if keys:
            rows = (await session.execute(
                select(PostureResultRow).where(PostureResultRow.scan_id == latest.id,
                                               PostureResultRow.namespace.in_({k[0] for k in keys}))
            )).scalars().all()
            for r in rows:
                if (r.namespace, r.kind, r.name) not in keys:
                    continue
                if r.container and (r.namespace, r.kind, r.name, r.container) not in cnames:
                    continue
                check = CHECKS_BY_ID.get(r.check_id)
                posture.append({"checkId": r.check_id, "title": check.title if check else r.check_id,
                                "severity": r.severity, "status": r.status, "namespace": r.namespace,
                                "kind": r.kind, "name": r.name, "container": r.container, "detail": r.detail,
                                "controls": check.controls if check else [],
                                "remediation": check.remediation if check else None,
                                "systemNamespace": r.system_namespace})
    runs = (await session.execute(
        select(ImageScan).where(ImageScan.image_id == image_id).order_by(ImageScan.id.desc()).limit(30)
    )).scalars().all()
    out = image_summary(img)
    out.update({
        "penalty": img.penalty,
        "findings": fl,
        "usedBy": used_by,
        "scans": [image_scan_dict(r) for r in runs],
        "postureFindings": sorted(posture, key=lambda p: (p["status"] != "fail", -severity_rank(p["severity"]))),
        "severityCounts": counts_of(img.counts),
    })
    return out


@router.get("/images/{image_id}/scans/{image_scan_id}/raw")
async def get_raw(image_id: int, image_scan_id: int, session: AsyncSession = Depends(get_session)) -> Response:
    row = await session.get(ImageScan, image_scan_id)
    if row is None or row.image_id != image_id or row.raw_gz is None:
        raise HTTPException(404, detail="raw scanner output not available")
    headers = {"X-Truncated": "true" if row.truncated else "false"}
    return Response(gzip.decompress(row.raw_gz), media_type="application/json", headers=headers)
