"""`GET /compliance/controls` (DESIGN §11). Other /compliance and /reports routes are
owned by the reports package."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..controls import all_controls, check_controls, control_title, vuln_controls
from ..db.models import ConsensusFindingRow, Image, PostureResultRow
from ..db.session import get_session
from ..views import latest_done_scan

router = APIRouter(tags=["compliance"])


async def control_coverage(session: AsyncSession) -> list[dict[str, Any]]:
    latest = await latest_done_scan(session)
    findings: dict[str, int] = {}
    checks: dict[str, int] = {}
    if latest is not None:
        for fixable, n in (await session.execute(
            select(ConsensusFindingRow.fixable, func.count()).join(Image, Image.id == ConsensusFindingRow.image_id)
            .where(Image.running.is_(True)).group_by(ConsensusFindingRow.fixable)
        )).all():
            for c in vuln_controls(bool(fixable)):
                findings[c] = findings.get(c, 0) + n
        for cid, n in (await session.execute(
            select(PostureResultRow.check_id, func.count())
            .where(PostureResultRow.scan_id == latest.id, PostureResultRow.status == "fail")
            .group_by(PostureResultRow.check_id)
        )).all():
            for c in check_controls(cid):
                checks[c] = checks.get(c, 0) + n
    out = []
    for c in all_controls():
        f, k = findings.get(c, 0), checks.get(c, 0)
        status = "not_assessed" if latest is None else ("open" if f or k else "satisfied")
        out.append({"control": c, "title": control_title(c), "findingsOpen": f, "checksFailed": k, "status": status})
    return out


@router.get("/compliance/controls")
async def controls(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    return await control_coverage(session)
