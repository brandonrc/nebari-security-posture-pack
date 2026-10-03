"""Native supply-chain endpoints (DESIGN §12): `/api/v1/supply-chain`, `/api/v1/helm-releases`."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..db.models import Image, Scan, ScanSnapshot
from ..db.session import get_session
from ..provenance.models import HelmReleaseRow, ImageProvenance
from ..provenance.report import report_scans
from ..provenance.scoring import cluster_supply_chain_score
from ..scoring import grade
from ..views import current_image_ids, iso

router = APIRouter(tags=["supply-chain"])

LIST_LIMIT = 200


def _any_update(updates: dict[str, Any] | None) -> dict[str, Any] | None:
    flagged = [u for u in (updates or {}).values() if (u or {}).get("updateAvailable")]
    return flagged[0] if flagged else None


async def _cluster_supply_score(session: AsyncSession, scan: Scan) -> float | None:
    snap = (await session.execute(
        select(ScanSnapshot).where(ScanSnapshot.scan_id == scan.id, ScanSnapshot.level == "cluster").limit(1)
    )).scalar_one_or_none()
    return (snap.data or {}).get("supplyChainScore") if snap is not None else None


async def latest_provenance_scan(session: AsyncSession) -> Scan | None:
    scans = await report_scans(session, limit=1)
    return scans[0] if scans else None


async def supply_chain_summary(session: AsyncSession, include_lists: bool = False,
                               include_stale: bool = False) -> dict[str, Any]:
    """Aggregates over the provenance scan's images. By default only images in the latest
    done scan's inventory count (`views.current_image_ids`), so the numbers match the scan's
    image count; `include_stale` adds images that are no longer deployed."""
    settings = await app_settings.load(session)
    ps = settings.provenance
    scan = await latest_provenance_scan(session)
    out: dict[str, Any] = {
        "enabled": ps.enabled, "signed": 0, "verified": 0, "withSbom": 0, "withProvenance": 0, "withUpdates": 0,
        "unique": 0, "helmReleases": 0, "helmWithUpdates": 0, "errors": 0, "score": None, "grade": "?",
        "scanId": None, "checkedAt": None, "includeStale": include_stale, "stale": 0,
        "verificationConfigured": bool(ps.verify_signatures and (ps.cosign_public_key or (
            ps.cosign_certificate_identity_regexp and ps.cosign_certificate_oidc_issuer_regexp))),
        "checks": {"signatures": ps.verify_signatures, "sbom": ps.check_sbom, "provenance": ps.check_provenance,
                   "updates": ps.check_updates, "helmReleases": ps.helm_releases},
    }
    if include_lists:
        out.update({"unsigned": [], "unverified": [], "outdated": [], "withoutSbom": [], "withoutProvenance": []})
    if scan is None:
        return out
    rows = list((await session.execute(
        select(ImageProvenance, Image).join(Image, Image.id == ImageProvenance.image_id)
        .where(ImageProvenance.scan_id == scan.id).order_by(Image.ref)
    )).all())
    current = None if include_stale else await current_image_ids(session)
    if current is not None:
        out["stale"] = sum(1 for _, img in rows if img.id not in current)
        rows = [(p, img) for p, img in rows if img.id in current]
    helm = list((await session.execute(select(HelmReleaseRow).where(HelmReleaseRow.scan_id == scan.id))).scalars())
    out["scanId"] = scan.id
    out["checkedAt"] = iso(max((p.checked_at for p, _ in rows), default=None))
    out["unique"] = len(rows)
    for p, img in rows:
        sig, upd = p.signature or {}, _any_update(p.updates)
        ref = {"imageId": img.id, "ref": img.ref, "digest": img.digest, "running": img.running, "score": p.score}
        if sig.get("signed"):
            out["signed"] += 1
            if sig.get("verified"):
                out["verified"] += 1
            elif include_lists:
                out["unverified"].append({**ref, "error": sig.get("error")})
        elif include_lists and p.signature is not None:
            out["unsigned"].append({**ref, "error": sig.get("error")})
        if (p.sbom or {}).get("hasSBOM"):
            out["withSbom"] += 1
        elif include_lists and p.sbom is not None:
            out["withoutSbom"].append(ref)
        if (p.provenance or {}).get("hasProvenance"):
            out["withProvenance"] += 1
        elif include_lists and p.provenance is not None:
            out["withoutProvenance"].append(ref)
        if upd:
            out["withUpdates"] += 1
            if include_lists:
                out["outdated"].append({**ref, **upd})
        if p.error:
            out["errors"] += 1
    out["helmReleases"] = len(helm)
    out["helmWithUpdates"] = sum(1 for h in helm if (h.update or {}).get("updateAvailable"))
    score = await _cluster_supply_score(session, scan)
    if score is None:  # scan still running / snapshot without supply chain: unweighted image mean
        score = cluster_supply_chain_score(p.score for p, _ in rows)
    out["score"], out["grade"] = score, grade(score)
    if include_lists:
        for k in ("unsigned", "unverified", "outdated", "withoutSbom", "withoutProvenance"):
            out[k] = out[k][:LIST_LIMIT]
    return out


@router.get("/supply-chain")
async def supply_chain(include_stale: bool = Query(False, alias="includeStale"),
                       session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await supply_chain_summary(session, include_lists=True, include_stale=include_stale)


@router.get("/helm-releases")
async def helm_releases(namespace: str | None = None, session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    scan = await latest_provenance_scan(session)
    if scan is None:
        return []
    stmt = select(HelmReleaseRow).where(HelmReleaseRow.scan_id == scan.id)
    if namespace:
        stmt = stmt.where(HelmReleaseRow.namespace.in_(namespace.split(",")))
    rows = (await session.execute(stmt.order_by(HelmReleaseRow.namespace, HelmReleaseRow.release_name))).scalars()
    out = []
    for h in rows:
        rec: dict[str, Any] = {"releaseName": h.release_name, "namespace": h.namespace, "chart": h.chart,
                               "version": h.version, "appVersion": h.app_version, "status": h.status}
        if h.update:
            rec["update"] = h.update
        rec.update({"revision": h.revision, "lastDeployed": h.last_deployed, "chartSource": h.chart_source,
                    "scanId": h.scan_id})
        out.append(rec)
    return out
