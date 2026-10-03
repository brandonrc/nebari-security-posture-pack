from __future__ import annotations

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
    freshness_warnings,
    iso,
    latest_done_scan,
    scanner_dict,
    scanner_rows,
    sla_due,
    utcnow,
)

router = APIRouter(tags=["summary"])


async def compute_sla_overdue(session: AsyncSession, sla: dict[str, int]) -> dict[str, int]:
    out = {k: 0 for k in ("critical", "high", "medium", "low")}
    rows = (await session.execute(
        select(ConsensusFindingRow.severity, ConsensusFindingRow.first_seen_at)
        .join(Image, Image.id == ConsensusFindingRow.image_id)
        .where(Image.running.is_(True), Image.score.isnot(None),
               ConsensusFindingRow.severity.in_(list(out)))
    )).all()
    now = utcnow()
    for sev, first_seen in rows:
        due = sla_due(first_seen, sev, sla)
        if due and now > due:
            out[sev] += 1
    return out


async def build_summary(session: AsyncSession) -> dict[str, Any]:
    settings = await app_settings.load(session)
    latest = await latest_done_scan(session)
    last_scan = (await session.execute(select(Scan).order_by(Scan.id.desc()).limit(1))).scalar_one_or_none()

    running_imgs = (await session.execute(select(Image).where(Image.running.is_(True)))).scalars().all()
    counts, fixable = zero_counts(), zero_counts()
    scanned = failed = 0
    for img in running_imgs:
        if img.score is not None:
            scanned += 1
            for k, v in counts_of(img.counts).items():
                counts[k] += v
            for k, v in counts_of(img.fixable).items():
                fixable[k] += v
        elif img.last_scanned_at is not None:
            failed += 1

    workloads = namespaces = 0
    checks = {"passed": 0, "failed": 0, "total": 0}
    if latest:
        workloads = await session.scalar(select(func.count()).select_from(WorkloadRow)
                                         .where(WorkloadRow.scan_id == latest.id)) or 0
        namespaces = await session.scalar(select(func.count(func.distinct(WorkloadRow.namespace)))
                                          .where(WorkloadRow.scan_id == latest.id)) or 0
        for status, n in (await session.execute(
            select(PostureResultRow.status, func.count()).where(PostureResultRow.scan_id == latest.id)
            .group_by(PostureResultRow.status)
        )).all():
            checks["passed" if status == "pass" else "failed"] += n
        checks["total"] = checks["passed"] + checks["failed"]

    trend_rows = (await session.execute(
        select(Scan, ScanSnapshot).join(ScanSnapshot, (ScanSnapshot.scan_id == Scan.id) & (ScanSnapshot.level == "cluster"))
        .where(Scan.status == "done").order_by(Scan.id.desc()).limit(30)
    )).all()
    trend = [{
        "scanId": sc.id, "finishedAt": iso(sc.finished_at), "score": snap.score, "grade": snap.grade,
        "critical": int(((snap.data or {}).get("counts") or {}).get("critical", 0)),
        "high": int(((snap.data or {}).get("counts") or {}).get("high", 0)),
    } for sc, snap in reversed(trend_rows)]

    top = sorted((i for i in running_imgs if i.score is not None), key=lambda i: (i.score, -i.id))[:10]
    top_risks = [{"imageId": i.id, "ref": i.ref, "score": i.score, "grade": i.grade,
                  "critical": counts_of(i.counts)["critical"], "high": counts_of(i.counts)["high"],
                  "workloads": i.workloads} for i in top]

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
        "images": {"total": len(running_imgs), "scanned": scanned, "failed": failed},
        "workloads": workloads,
        "namespaces": namespaces,
        "scanners": scanners,
        "trend": trend,
        "topRisks": top_risks,
        "checks": checks,
        "slaOverdue": await compute_sla_overdue(session, settings.remediation_sla_days.model_dump()),
        "warnings": warnings,
        "supplyChain": supply,
    }


@router.get("/summary")
async def summary(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await build_summary(session)
