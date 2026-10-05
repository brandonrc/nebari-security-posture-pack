from __future__ import annotations

import gzip
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import case, func, or_, select
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
    # DESIGN §14: STIG score; images without one sort last in either order (see list_images)
    "stig": lambda d: ((d.get("stig") or {}).get("score") is None, (d.get("stig") or {}).get("score") or 0),
}
STIG_FILTERS = ("evaluated", "na", "cat1")


def stig_filter(d: dict[str, Any], value: str) -> bool:
    """`stig=` filter (comma list, any matches): evaluated = at least one benchmark result;
    na = notApplicable or noContent (no SCAP benchmark / no content for it); cat1 = >= 1 open CAT I."""
    st = d.get("stig") or {}
    for v in (x.strip().lower() for x in value.split(",") if x.strip()):
        if v == "evaluated" and st.get("status") == "evaluated":
            return True
        if v == "na" and st.get("status") in ("notApplicable", "noContent"):
            return True
        if v == "cat1" and int(st.get("cat1Open") or 0) > 0:
            return True
    return False


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
    stig: str | None = None,
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
    if stig:
        items = [d for d in items if stig_filter(d, stig)]
    keyfn = SORT_KEYS.get(sort, SORT_KEYS["score"])
    default_desc = sort not in ("score", "ref", "grade", "stig")
    desc = (order or ("desc" if default_desc else "asc")).lower() == "desc"
    items.sort(key=keyfn, reverse=desc)
    if sort == "score":  # unscored images always last
        items.sort(key=lambda d: d["score"] is None)
    if sort == "stig":  # images without a STIG score always last
        items.sort(key=lambda d: (d.get("stig") or {}).get("score") is None)
    total = len(items)
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total, "page": page, "pageSize": page_size}


async def _image_or_404(session: AsyncSession, image_id: int) -> Image:
    img = await session.get(Image, image_id)
    if img is None:
        raise HTTPException(404, detail="image not found")
    return img


UNPAGED_LIMIT = 500  # findings returned when the client sends no `page` (the UI before server paging)
_SEV_RANK = case({s: severity_rank(s) for s in SEVERITIES}, value=ConsensusFindingRow.severity, else_=0)


def _finding_order(sort: str, order: str) -> list[Any]:
    c = ConsensusFindingRow
    desc = order.lower() != "asc"
    cols = {
        "severity": [_SEV_RANK, func.coalesce(c.cvss, 0.0)],
        "cvss": [func.coalesce(c.cvss, 0.0), _SEV_RANK],
        "vulnId": [c.vuln_id],
        "package": [c.package],
        "agreement": [func.jsonb_array_length(c.scanners), _SEV_RANK],
        "firstSeenAt": [c.first_seen_at],
    }.get(sort) or [_SEV_RANK, func.coalesce(c.cvss, 0.0)]
    out = [x.desc() if desc else x.asc() for x in cols]
    # stable tie-break: vulnId asc, package asc (the old in-memory order)
    return out + [c.vuln_id.asc(), c.package.asc(), c.id.asc()]


async def findings_page(session: AsyncSession, img: Image, sla: dict[str, int], *, page: int | None,
                        page_size: int, severity: str | None, q: str | None, fixable: bool | None,
                        disagree: bool | None, sort: str, order: str) -> dict[str, Any]:
    """Findings of one image filtered, sorted and paginated in SQL, plus a summary over the
    filtered set (totals by severity, fixable, flagged by all scanners that succeeded)."""
    c = ConsensusFindingRow
    ok_scanners = sum(1 for r in (img.scanners or {}).values() if (r or {}).get("status") == "ok")
    conds = [c.image_id == img.id]
    if severity:
        conds.append(c.severity.in_([x.strip().lower() for x in severity.split(",") if x.strip()] or ["-"]))
    if q:
        needle = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conds.append(or_(func.lower(c.vuln_id).like(needle, escape="\\"), func.lower(c.package).like(needle, escape="\\"),
                         func.lower(func.coalesce(c.title, "")).like(needle, escape="\\")))
    if fixable is not None:
        conds.append(c.fixable.is_(fixable))
    if disagree:
        conds.append(func.jsonb_array_length(c.scanners) < ok_scanners)
    all_agree = func.jsonb_array_length(c.scanners) >= ok_scanners
    by_sev = dict((await session.execute(select(c.severity, func.count()).where(*conds).group_by(c.severity))).all())
    agg = (await session.execute(select(
        func.count(), func.count().filter(c.fixable.is_(True)),
        func.count().filter(all_agree) if ok_scanners > 1 else func.sum(0),
    ).where(*conds))).one()
    filtered = int(agg[0] or 0)
    image_total = filtered if len(conds) == 1 else (await session.scalar(
        select(func.count()).select_from(c).where(c.image_id == img.id)) or 0)
    stmt = select(c).where(*conds).order_by(*_finding_order(sort, order))
    if page is None:
        size, start = UNPAGED_LIMIT, 0
    else:
        size, start = page_size, (page - 1) * page_size
    rows = (await session.execute(stmt.offset(start).limit(size))).scalars().all()
    return {
        "findings": [finding_dict(f, sla) for f in rows],
        "findingsTotal": filtered,
        "findingsPage": page or 1,
        "findingsPageSize": size,
        "truncated": page is None and filtered > UNPAGED_LIMIT,
        "findingsSummary": {"total": image_total, "filtered": filtered,
                            "bySeverity": {sev: int(by_sev.get(sev, 0)) for sev in SEVERITIES},
                            "fixable": int(agg[1] or 0), "flaggedByAll": int(agg[2] or 0),
                            "scannersOk": ok_scanners},
    }


@router.get("/images/{image_id}")
async def get_image(
    image_id: int,
    page: int | None = Query(None, ge=1),
    pageSize: int = Query(50, alias="pageSize"),  # noqa: N803
    severity: str | None = None,
    q: str | None = Query(None, max_length=200),
    fixable: bool | None = None,
    disagree: bool | None = None,
    sort: str = "severity",
    order: str = "desc",
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Image detail. Findings are paginated in SQL when `page` is given (`pageSize` default 50,
    max 500); without `page` the first 500 come back with `truncated: true` when there are more
    (the UI before server-side paging; DECISIONS 2026-10-03)."""
    img = await _image_or_404(session, image_id)
    settings = await app_settings.load(session)
    sla = settings.remediation_sla_days.model_dump()
    _, page_size = page_params(page or 1, pageSize)
    fpage = await findings_page(session, img, sla, page=page, page_size=page_size, severity=severity, q=q,
                                fixable=fixable, disagree=disagree, sort=sort, order=order)
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
        **fpage,
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
