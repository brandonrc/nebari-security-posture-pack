from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..controls import vuln_controls
from ..db.models import ConsensusFindingRow, ContainerRow, Image
from ..db.session import get_session
from ..severity import SEVERITIES, max_severity, severity_rank
from ..views import finding_dict, latest_done_scan, page_params

router = APIRouter(tags=["vulnerabilities"])


async def _workloads_by_image(session: AsyncSession) -> dict[int, set[tuple[str, str, str]]]:
    latest = await latest_done_scan(session)
    out: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    if latest is None:
        return out
    for img_id, ns, kind, name in (await session.execute(
        select(ContainerRow.image_fk, ContainerRow.namespace, ContainerRow.workload_kind, ContainerRow.workload_name)
        .where(ContainerRow.scan_id == latest.id, ContainerRow.image_fk.isnot(None))
    )).all():
        out[img_id].add((ns, kind, name))
    return out


async def _rows(session: AsyncSession, vuln_id: str | None = None):
    stmt = (select(ConsensusFindingRow, Image).join(Image, Image.id == ConsensusFindingRow.image_id)
            .where(Image.running.is_(True)))
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


@router.get("/vulnerabilities")
async def list_vulns(
    severity: str | None = None,
    q: str | None = None,
    fixable: bool | None = None,
    sort: str = "severity",
    order: str = "desc",
    page: int = 1,
    pageSize: int = Query(50, alias="pageSize"),  # noqa: N803
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    page, page_size = page_params(page, pageSize)
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
    return {"items": items[start:start + page_size], "total": total, "page": page, "pageSize": page_size}


@router.get("/vulnerabilities/{vuln_id}")
async def get_vuln(vuln_id: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    rows = await _rows(session, vuln_id)
    if not rows:
        raise HTTPException(404, detail="vulnerability not found in running images")
    wl = await _workloads_by_image(session)
    detail = group_by_vuln(rows, wl)[vuln_id]
    sla = (await app_settings.load(session)).remediation_sla_days.model_dump()
    detail["images"] = [{
        "imageId": img.id, "ref": img.ref, "digest": img.digest, "score": img.score, "grade": img.grade,
        "namespaces": img.namespaces or [], "workloads": sorted(f"{w[0]}/{w[1]}/{w[2]}" for w in wl.get(img.id, set())),
        **finding_dict(c, sla),
    } for c, img in sorted(rows, key=lambda r: (-severity_rank(r[0].severity), r[1].ref))]
    return detail
