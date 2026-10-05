from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..db.models import ConsensusFindingRow, Image, PostureResultRow, Scan, ScanSnapshot, WorkloadRow
from ..db.session import get_session
from ..severity import zero_counts
from ..views import (
    SCANNERS,
    counts_of,
    current_image_ids,
    freshness_warnings,
    iso,
    latest_done_scan,
    scanner_dict,
    scanner_rows,
    scanner_succeeded,
    utcnow,
)

from .stig import stig_summary

router = APIRouter(tags=["summary"])


async def compute_sla_overdue(session: AsyncSession, sla: dict[str, int]) -> dict[str, int]:
    """Open findings past their remediation SLA on running, scored images (counted in SQL)."""
    out = {k: 0 for k in ("critical", "high", "medium", "low")}
    c = ConsensusFindingRow
    now = utcnow()
    for sev in out:
        days = sla.get(sev)
        if not days:
            continue
        out[sev] = await session.scalar(
            select(func.count()).select_from(c).join(Image, Image.id == c.image_id)
            .where(Image.running.is_(True), Image.score.isnot(None), c.severity == sev, c.open_filter(),
                   c.first_seen_at < now - timedelta(days=days))) or 0
    return out


async def kev_exposure(session: AsyncSession) -> dict[str, Any]:
    """Open findings on running images that are in the CISA KEV catalog (count, distinct CVEs,
    the earliest KEV due date, and how many are past it)."""
    from ..reports.kev import catalog, lookup

    rows = (await session.execute(
        select(ConsensusFindingRow.vuln_id, func.count()).join(Image, Image.id == ConsensusFindingRow.image_id)
        .where(Image.running.is_(True), ConsensusFindingRow.vuln_id.like("CVE-%"), ConsensusFindingRow.open_filter())
        .group_by(ConsensusFindingRow.vuln_id))).all()
    today = utcnow().date()
    findings, cves, overdue, due = 0, [], 0, None
    for vid, n in rows:
        e = lookup(vid)
        if e is None:
            continue
        findings += int(n)
        cves.append(vid)
        if e.due:
            due = e.due if due is None or e.due < due else due
            if e.due < today:
                overdue += int(n)
    cat = catalog()
    return {"kev": findings, "kevCves": len(cves), "kevOverdue": overdue,
            "kevEarliestDue": due.isoformat() if due else None, "kevCatalogVersion": cat.get("version"),
            "topKev": sorted(cves)[:20]}


async def vex_suppressed_count(session: AsyncSession) -> int:
    """Findings on running images that a `not_affected` VEX statement suppresses (kept, not open)."""
    c = ConsensusFindingRow
    return int(await session.scalar(
        select(func.count()).select_from(c).join(Image, Image.id == c.image_id)
        .where(Image.running.is_(True), c.vex_status == "not_affected")) or 0)


async def build_summary(session: AsyncSession) -> dict[str, Any]:
    settings = await app_settings.load(session)
    latest = await latest_done_scan(session)
    last_scan = (await session.execute(select(Scan).order_by(Scan.id.desc()).limit(1))).scalar_one_or_none()

    # counts, fixable and top risks: written once per scan into the cluster snapshot (M4);
    # computed from the images only for scans finished before that
    cluster = None
    if latest is not None:
        cluster = (await session.execute(select(ScanSnapshot).where(
            ScanSnapshot.scan_id == latest.id, ScanSnapshot.level == "cluster").limit(1))).scalar_one_or_none()
    cdata = (cluster.data or {}) if cluster is not None else {}
    running_imgs: list[Image] | None = None
    if "topRisks" in cdata and "fixable" in cdata:
        counts, fixable = counts_of(cdata.get("counts")), counts_of(cdata.get("fixable"))
        top_risks = list(cdata["topRisks"])
    else:
        running_imgs = list((await session.execute(select(Image).where(Image.running.is_(True)))).scalars())
        counts, fixable = zero_counts(), zero_counts()
        for img in running_imgs:
            if img.score is not None:
                for k, v in counts_of(img.counts).items():
                    counts[k] += v
                for k, v in counts_of(img.fixable).items():
                    fixable[k] += v
        top = sorted((i for i in running_imgs if i.score is not None), key=lambda i: (i.score, -i.id))[:10]
        top_risks = [{"imageId": i.id, "ref": i.ref, "score": i.score, "grade": i.grade,
                      "critical": counts_of(i.counts)["critical"], "high": counts_of(i.counts)["high"],
                      "workloads": i.workloads} for i in top]
    # images.*: the latest done scan's unique images (same set as its imagesTotal), so the
    # Overview agrees with the scan row; `running` = those with a Running pod (counts above).
    current_ids = await current_image_ids(session, latest)
    if current_ids is None:  # no completed scan yet
        current_imgs = list(running_imgs if running_imgs is not None else (await session.execute(
            select(Image).where(Image.running.is_(True)))).scalars())
    else:
        current_imgs = list((await session.execute(
            select(Image).where(Image.id.in_(current_ids or {-1})))).scalars())
    images = {"total": len(current_imgs), "scanned": sum(1 for i in current_imgs if i.score is not None),
              "failed": sum(1 for i in current_imgs if i.score is None and not scanner_succeeded(i)),
              "running": sum(1 for i in current_imgs if i.running)}

    workloads = namespaces = 0
    checks = {"passed": 0, "failed": 0, "acceptedRisk": 0, "total": 0}
    if latest:
        workloads = await session.scalar(select(func.count()).select_from(WorkloadRow)
                                         .where(WorkloadRow.scan_id == latest.id)) or 0
        namespaces = await session.scalar(select(func.count(func.distinct(WorkloadRow.namespace)))
                                          .where(WorkloadRow.scan_id == latest.id)) or 0
        for status, n in (await session.execute(
            select(PostureResultRow.status, func.count()).where(PostureResultRow.scan_id == latest.id)
            .group_by(PostureResultRow.status)
        )).all():
            checks[{"pass": "passed", "accepted-risk": "acceptedRisk"}.get(status, "failed")] += n
        checks["total"] = checks["passed"] + checks["failed"] + checks["acceptedRisk"]

    trend_rows = (await session.execute(
        select(Scan, ScanSnapshot).join(ScanSnapshot, (ScanSnapshot.scan_id == Scan.id) & (ScanSnapshot.level == "cluster"))
        .where(Scan.status == "done").order_by(Scan.id.desc()).limit(30)
    )).all()
    trend = [{
        "scanId": sc.id, "finishedAt": iso(sc.finished_at), "score": snap.score, "grade": snap.grade,
        "critical": int(((snap.data or {}).get("counts") or {}).get("critical", 0)),
        "high": int(((snap.data or {}).get("counts") or {}).get("high", 0)),
    } for sc, snap in reversed(trend_rows)]

    enabled = settings.scanners.model_dump()
    srows = await scanner_rows(session)
    scanners = [{k: v for k, v in scanner_dict(n, srows.get(n), enabled[n]).items() if k != "lastRunAt"}
                for n in SCANNERS]
    warnings = freshness_warnings(srows, enabled)
    if latest is None:
        warnings.append("no scan has completed yet")

    from .supply_chain import supply_chain_summary

    supply = await supply_chain_summary(session)
    previous = None
    if len(trend) >= 2:
        previous = trend[-2]["score"]
    score = latest.score if latest else None
    return {
        "score": score,
        "grade": latest.grade if latest and latest.grade else "?",
        "vulnScore": latest.vuln_score if latest else None,
        "postureScore": latest.posture_score if latest else None,
        "supplyChainScore": supply["score"],  # DESIGN §12 (cluster weight 0.15 when present)
        "previousScore": previous,
        "delta": round(score - previous, 1) if score is not None and previous is not None else None,
        "generatedAt": iso(utcnow()),
        "lastScan": None if last_scan is None else {
            "id": last_scan.id, "status": last_scan.status, "startedAt": iso(last_scan.started_at),
            "finishedAt": iso(last_scan.finished_at), "imagesTotal": last_scan.images_total,
            "imagesDone": last_scan.images_done, "imagesFailed": last_scan.images_failed,
        },
        "counts": counts,
        "fixable": fixable,
        "vexSuppressed": await vex_suppressed_count(session),  # not in counts / fixable / score
        "images": images,
        "workloads": workloads,
        "namespaces": namespaces,
        "scanners": scanners,
        "trend": trend,
        "topRisks": top_risks,
        "checks": checks,
        "slaOverdue": await compute_sla_overdue(session, settings.remediation_sla_days.model_dump()),
        "warnings": warnings,
        "supplyChain": supply,
        "exposure": await kev_exposure(session),  # compliance review S4: CISA KEV, never down-weighted
        "stig": await stig_summary(session, current_ids),  # DESIGN §14 (OS / product STIGs in images)
    }


@router.get("/summary")
async def summary(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await build_summary(session)
