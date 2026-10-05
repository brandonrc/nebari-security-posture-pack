from __future__ import annotations

import base64
import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..controls import vuln_controls
from ..db.models import ConsensusFindingRow, ContainerRow, Image, VulnRollupRow
from ..db.session import get_session
from ..severity import SEVERITIES, max_severity, severity_rank
from ..views import finding_dict, iso, latest_done_scan, page_params

router = APIRouter(tags=["vulnerabilities"])
SORTS = ("severity", "imagesAffected", "workloadsAffected", "cvss", "agreement", "firstSeen", "vulnId")


async def _workloads_by_image(session: AsyncSession,
                              image_ids: set[int] | None = None) -> dict[int, set[tuple[str, str, str]]]:
    latest = await latest_done_scan(session)
    out: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    if latest is None:
        return out
    stmt = (select(ContainerRow.image_fk, ContainerRow.namespace, ContainerRow.workload_kind,
                   ContainerRow.workload_name)
            .where(ContainerRow.scan_id == latest.id, ContainerRow.image_fk.isnot(None)))
    if image_ids is not None:
        stmt = stmt.where(ContainerRow.image_fk.in_(image_ids or {0}))
    for img_id, ns, kind, name in (await session.execute(stmt)).all():
        out[img_id].add((ns, kind, name))
    return out


async def _rows(session: AsyncSession, vuln_id: str | None = None):
    stmt = (select(ConsensusFindingRow, Image).join(Image, Image.id == ConsensusFindingRow.image_id)
            .where(Image.running.is_(True), ConsensusFindingRow.open_filter()))  # as the rollup
    if vuln_id:
        stmt = stmt.where(ConsensusFindingRow.vuln_id == vuln_id)
    return (await session.execute(stmt)).all()


def group_by_vuln(rows, wl_by_image) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for c, img in rows:
        g = groups.setdefault(c.vuln_id, {"vulnId": c.vuln_id, "_sev": [], "_scanners": set(), "_agree": [],
                                         "_images": set(), "_workloads": set(), "fixAvailable": False,
                                         "cvss": None, "title": None, "url": None, "_packages": set()})
        g["_sev"].append(c.severity)
        g["_scanners"].update(c.scanners or [])
        g["_agree"].append(c.agreement)
        g["_images"].add(img.id)
        g["_workloads"].update(wl_by_image.get(img.id, set()))
        g["_packages"].add(c.package)
        g["fixAvailable"] = g["fixAvailable"] or c.fixable
        if c.cvss and (g["cvss"] is None or c.cvss > g["cvss"]):
            g["cvss"] = c.cvss
        g["title"] = g["title"] or c.title
        g["url"] = g["url"] or c.url
    out = {}
    for vid, g in groups.items():
        order = [s for s in ("trivy", "grype", "clair") if s in g["_scanners"]]
        out[vid] = {
            "vulnId": vid,
            "severity": max_severity(g["_sev"]),
            "scanners": order,
            "agreement": round(max(g["_agree"]), 4) if g["_agree"] else 0,
            "imagesAffected": len(g["_images"]),
            "workloadsAffected": len(g["_workloads"]),
            "fixAvailable": g["fixAvailable"],
            "cvss": g["cvss"],
            "title": g["title"],
            "url": g["url"],
            "packages": sorted(g["_packages"]),
            "controls": vuln_controls(g["fixAvailable"]),
        }
    return out


# sort -> columns, compared as one tuple (keyset pagination); vulnId breaks ties
def _sort_cols(sort: str) -> list[Any]:
    v = VulnRollupRow
    cvss = func.coalesce(v.cvss, 0.0)
    return {
        "severity": [v.severity_rank, cvss, v.images_affected],
        "imagesAffected": [v.images_affected, v.severity_rank],
        "workloadsAffected": [v.workloads_affected, v.severity_rank],
        "cvss": [cvss],
        "agreement": [v.agreement, v.severity_rank],
        "firstSeen": [func.coalesce(v.first_seen, datetime(1970, 1, 1, tzinfo=UTC))],
        "vulnId": [],
    }[sort]


def _encode_cursor(values: list[Any]) -> str:
    out = [x.isoformat() if isinstance(x, datetime) else x for x in values]
    return base64.urlsafe_b64encode(json.dumps(out).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str, n: int, sort: str) -> list[Any]:
    try:
        vals = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (ValueError, TypeError):
        raise HTTPException(400, detail="invalid cursor") from None
    if not isinstance(vals, list) or len(vals) != n:
        raise HTTPException(400, detail="invalid cursor")
    if sort == "firstSeen":
        vals[0] = datetime.fromisoformat(vals[0])
    return vals


def rollup_item(r: VulnRollupRow) -> dict[str, Any]:
    return {
        "vulnId": r.vuln_id,
        "severity": r.severity,
        "scanners": list(r.scanners or []),
        "agreement": r.agreement,
        "imagesAffected": r.images_affected,
        "workloadsAffected": r.workloads_affected,
        "fixAvailable": r.fix_available,
        "cvss": r.cvss,
        "kev": r.kev,
        "title": r.title,
        "url": r.url,
        "firstSeenAt": iso(r.first_seen),
        "packages": list(r.packages or []),
        "controls": vuln_controls(r.fix_available),
    }


async def list_from_rollup(session: AsyncSession, scan_id: int, *, severity: str | None, q: str | None,
                           fixable: bool | None, kev: bool | None, sort: str, order: str, page: int, page_size: int,
                           cursor: str | None) -> dict[str, Any]:
    v = VulnRollupRow
    conds = [v.scan_id == scan_id]
    if severity:
        sevs = [s.strip().lower() for s in severity.split(",") if s.strip().lower() in SEVERITIES]
        conds.append(v.severity.in_(sevs or ["-"]))
    if q:
        needle = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds.append(v.search.like(f"%{needle}%", escape="\\"))  # pg_trgm GIN index
    if fixable is not None:
        conds.append(v.fix_available.is_(fixable))
    if kev is not None:
        conds.append(v.kev.is_(kev))
    total = await session.scalar(select(func.count()).select_from(v).where(*conds)) or 0
    cols = [*_sort_cols(sort), v.vuln_id]
    desc = order.lower() != "asc"
    stmt = select(v).where(*conds)
    if cursor:
        after = _decode_cursor(cursor, len(cols), sort)
        key = tuple_(*cols)
        stmt = stmt.where(key < tuple_(*after) if desc else key > tuple_(*after))
    else:
        stmt = stmt.offset((page - 1) * page_size)
    stmt = stmt.order_by(*[c.desc() if desc else c.asc() for c in cols]).limit(page_size + 1)
    rows = (await session.execute(stmt)).scalars().all()
    more = len(rows) > page_size
    rows = rows[:page_size]
    next_cursor = None
    if more and rows:
        last = rows[-1]
        vals = {"severity": [last.severity_rank, last.cvss or 0.0, last.images_affected],
                "imagesAffected": [last.images_affected, last.severity_rank],
                "workloadsAffected": [last.workloads_affected, last.severity_rank],
                "cvss": [last.cvss or 0.0], "agreement": [last.agreement, last.severity_rank],
                "firstSeen": [last.first_seen or datetime(1970, 1, 1, tzinfo=UTC)], "vulnId": []}
        next_cursor = _encode_cursor([*vals.get(sort, vals["severity"]), last.vuln_id])
    return {"items": [rollup_item(r) for r in rows], "total": total, "page": page, "pageSize": page_size,
            "nextCursor": next_cursor}


@router.get("/vulnerabilities")
async def list_vulns(
    severity: str | None = None,
    q: str | None = Query(None, max_length=200),
    fixable: bool | None = None,
    kev: bool | None = None,
    sort: str = "severity",
    order: str = "desc",
    page: int = 1,
    pageSize: int = Query(50, alias="pageSize"),  # noqa: N803
    cursor: str | None = Query(None, max_length=2000),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """CVE-centric list from the latest scan's `vuln_rollup` (SQL filter / sort / pagination;
    `cursor` = keyset pagination via the previous page's `nextCursor`)."""
    page, page_size = page_params(page, pageSize)
    if sort not in SORTS:
        sort = "severity"
    latest = await latest_done_scan(session)
    if latest is not None and latest.vuln_rollup_at is not None:
        return await list_from_rollup(session, latest.id, severity=severity, q=q, fixable=fixable, kev=kev,
                                      sort=sort, order=order, page=page, page_size=page_size, cursor=cursor)
    # no rollup yet (scan finished before the upgrade): group in Python once more
    items = list(group_by_vuln(await _rows(session), await _workloads_by_image(session)).values())
    if severity:
        sevs = {s.strip().lower() for s in severity.split(",") if s.strip().lower() in SEVERITIES}
        items = [i for i in items if i["severity"] in sevs]
    if q:
        ql = q.lower()
        items = [i for i in items if ql in i["vulnId"].lower() or ql in (i["title"] or "").lower()
                 or any(ql in p.lower() for p in i["packages"])]
    if fixable is not None:
        items = [i for i in items if i["fixAvailable"] == fixable]
    keys = {
        "severity": lambda i: (severity_rank(i["severity"]), i["cvss"] or 0, i["imagesAffected"]),
        "imagesAffected": lambda i: (i["imagesAffected"], severity_rank(i["severity"])),
        "workloadsAffected": lambda i: (i["workloadsAffected"], severity_rank(i["severity"])),
        "cvss": lambda i: (i["cvss"] or 0,),
        "agreement": lambda i: (i["agreement"], severity_rank(i["severity"])),
        "vulnId": lambda i: (i["vulnId"],),
    }
    items.sort(key=keys.get(sort, keys["severity"]), reverse=order.lower() != "asc")
    total = len(items)
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total, "page": page, "pageSize": page_size,
            "nextCursor": None}


@router.get("/vulnerabilities/{vuln_id}")
async def get_vuln(vuln_id: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    rows = await _rows(session, vuln_id)
    if not rows:
        raise HTTPException(404, detail="vulnerability not found in running images")
    wl = await _workloads_by_image(session, {img.id for _, img in rows})
    detail = group_by_vuln(rows, wl)[vuln_id]
    sla = (await app_settings.load(session)).remediation_sla_days.model_dump()
    detail["images"] = [{
        "imageId": img.id, "ref": img.ref, "digest": img.digest, "score": img.score, "grade": img.grade,
        "namespaces": img.namespaces or [], "workloads": sorted(f"{w[0]}/{w[1]}/{w[2]}" for w in wl.get(img.id, set())),
        **finding_dict(c, sla),
    } for c, img in sorted(rows, key=lambda r: (-severity_rank(r[0].severity), r[1].ref))]
    return detail
