from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..db.models import ConsensusFindingRow, Image
from ..db.session import get_session
from ..reports.cells import safe_cell
from ..severity import severity_rank
from ..views import finding_dict, image_summary, iso, utcnow
from .checks import list_checks
from .summary import build_summary
from .workloads import list_workloads, namespace_rows

router = APIRouter(tags=["export"])

CSV_COLUMNS = ["imageId", "imageRef", "digest", "running", "namespaces", "imageScore", "imageGrade", "vulnId",
               "severity", "package", "installedVersion", "fixedVersion", "fixable", "pkgType", "scanners",
               "agreement", "trivy", "grype", "clair", "cvss", "title", "url", "controls", "firstSeenAt", "slaDueAt",
               "vexStatus", "vexJustification", "vexSource"]


async def build_export(session: AsyncSession) -> dict[str, Any]:
    sla = (await app_settings.load(session)).remediation_sla_days.model_dump()
    imgs = (await session.execute(select(Image).order_by(Image.id))).scalars().all()
    findings: dict[int, list[dict[str, Any]]] = {}
    for c in (await session.execute(select(ConsensusFindingRow))).scalars():
        findings.setdefault(c.image_id, []).append(finding_dict(c, sla))
    images = []
    for i in imgs:
        d = image_summary(i)
        d["findings"] = sorted(findings.get(i.id, []), key=lambda f: (-severity_rank(f["severity"]), f["vulnId"]))
        images.append(d)
    return {
        "generatedAt": iso(utcnow()),
        "summary": await build_summary(session),
        "images": images,
        "workloads": await list_workloads(None, None, None, session),
        "namespaces": await namespace_rows(session),
        "checks": await list_checks(session),
    }


@router.get("/export")
async def export(format: str = "json", session: AsyncSession = Depends(get_session)) -> Response:  # noqa: A002
    fmt = format.lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(400, detail="format must be json or csv")
    data = await build_export(session)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    if fmt == "json":
        return Response(json.dumps(data, indent=1), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="security-posture-{stamp}.json"'})
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for img in data["images"]:
        for f in img["findings"]:
            w.writerow({k: safe_cell(v) for k, v in {
                "imageId": img["id"], "imageRef": img["ref"], "digest": img["digest"], "running": img["running"],
                "namespaces": " ".join(img["namespaces"]), "imageScore": img["score"], "imageGrade": img["grade"],
                **{k: f.get(k) for k in ("vulnId", "severity", "package", "installedVersion", "fixedVersion",
                                         "fixable", "pkgType", "agreement", "cvss", "title", "url", "firstSeenAt",
                                         "slaDueAt", "vexStatus", "vexJustification", "vexSource")},
                "scanners": " ".join(f["scanners"]), "controls": " ".join(f["controls"]),
                "trivy": f["perScanner"].get("trivy", ""), "grype": f["perScanner"].get("grype", ""),
                "clair": f["perScanner"].get("clair", ""),
            }.items()})  # formula-injection safe (security review M5)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="security-posture-{stamp}.csv"'})
