"""Control coverage from scan evidence (DESIGN §11). `GET /compliance/controls` itself is served by
routers/controls.py (DESIGN §13), which extends these rows with engine statuses. Other /compliance and
/reports routes are owned by the reports package."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..controls import all_controls, check_controls, control_title, vuln_controls
from ..db.models import ConsensusFindingRow, Image, PostureResultRow
from ..views import latest_done_scan

router = APIRouter(tags=["compliance"])


async def control_coverage(session: AsyncSession) -> list[dict[str, Any]]:
    latest = await latest_done_scan(session)
    findings: dict[str, int] = {}
    checks: dict[str, int] = {}
    accepted: dict[str, int] = {}
    if latest is not None:
        for fixable, n in (await session.execute(
            select(ConsensusFindingRow.fixable, func.count()).join(Image, Image.id == ConsensusFindingRow.image_id)
            .where(Image.running.is_(True), ConsensusFindingRow.open_filter()).group_by(ConsensusFindingRow.fixable)
        )).all():
            for c in vuln_controls(bool(fixable)):
                findings[c] = findings.get(c, 0) + n
        for cid, st, n in (await session.execute(
            select(PostureResultRow.check_id, PostureResultRow.status, func.count())
            .where(PostureResultRow.scan_id == latest.id, PostureResultRow.status.in_(("fail", "accepted-risk")))
            .group_by(PostureResultRow.check_id, PostureResultRow.status)
        )).all():
            target = checks if st == "fail" else accepted
            for c in check_controls(cid):
                target[c] = target.get(c, 0) + n
    out = []
    for c in all_controls():
        f, k, a = findings.get(c, 0), checks.get(c, 0), accepted.get(c, 0)
        # an accepted risk is never "satisfied" (controlsEngine.exceptions)
        status = "not_assessed" if latest is None else ("open" if f or k else "risk_accepted" if a else "satisfied")
        out.append({"control": c, "title": control_title(c), "findingsOpen": f, "checksFailed": k,
                    "checksAcceptedRisk": a, "status": status})
    return out

