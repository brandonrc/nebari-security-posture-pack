"""Query helpers + JSON shapes (camelCase) shared by routers, export and reports."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .controls import vuln_controls
from .db.models import ConsensusFindingRow, ContainerRow, Image, ImageScan, Scan, ScannerStatus
from .provenance import models as _provenance_models  # noqa: F401  (maps images.provenance, DESIGN §12)
from .scap import models as _scap_models  # noqa: F401  (maps images.stig, DESIGN §14)
from .severity import SEVERITIES, zero_counts

SCANNERS = ("trivy", "grype", "clair")
FRESHNESS_HOURS = 72


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def utcnow() -> datetime:
    return datetime.now(UTC)


def counts_of(d: dict[str, Any] | None) -> dict[str, int]:
    out = zero_counts()
    for k in SEVERITIES:
        out[k] = int((d or {}).get(k, 0) or 0)
    return out


async def latest_done_scan(session: AsyncSession) -> Scan | None:
    return (await session.execute(
        select(Scan).where(Scan.status == "done", Scan.inventory_complete.is_(True)).order_by(Scan.id.desc()).limit(1)
    )).scalar_one_or_none()


async def current_image_ids(session: AsyncSession, scan: Scan | None = None) -> set[int] | None:
    """Unique images in the inventory of `scan` (default: the latest done scan), i.e. the
    images deployed in the cluster at that scan; the same set as the scan's image count.
    Images seen only in older scans are *stale*. None when no scan has completed."""
    scan = scan or await latest_done_scan(session)
    if scan is None:
        return None
    rows = await session.execute(
        select(ContainerRow.image_fk).where(ContainerRow.scan_id == scan.id, ContainerRow.image_fk.isnot(None))
        .distinct())
    return {int(i) for (i,) in rows}


def scanner_succeeded(img: Image) -> bool:
    return any((r or {}).get("status") == "ok" for r in (img.scanners or {}).values())


# Scan rows in flight. `scanned` / `finalizing` are the hand-off between the scan worker and
# the privileged worker (posture.worker stages); clients see them as `running` plus `phase`.
ACTIVE_SCAN_STATUSES = ("queued", "running", "scanned", "finalizing")
INTERNAL_RUNNING = ("scanned", "finalizing")


def scan_dict(s: Scan) -> dict[str, Any]:
    return {
        "id": s.id,
        "trigger": s.trigger,
        "status": "running" if s.status in INTERNAL_RUNNING else s.status,
        "phase": s.status,
        "createdAt": iso(s.created_at),
        "startedAt": iso(s.started_at),
        "finishedAt": iso(s.finished_at),
        "imagesTotal": s.images_total,
        "imagesDone": s.images_done,
        "imagesFailed": s.images_failed,
        "imagesInventoried": s.images_inventoried,
        "imagesRescanned": s.images_rescanned,
        "imagesSkippedFresh": s.images_skipped_fresh,
        "imagesTargeted": s.images_targeted,
        "score": s.score,
        "grade": s.grade,
        "vulnScore": s.vuln_score,
        "postureScore": s.posture_score,
        "requestedBy": s.requested_by,
        "force": s.force,
        "targetImageIds": s.target_image_ids,
        "targetNamespaces": s.target_namespaces,
        "error": s.error,
        # DESIGN §14: null (SCAP disabled) | queued | running | done | skipped | failed. A done scan
        # whose scapStatus is still queued / running finished with "scap pending".
        "scapStatus": s.scap_status,
        "scapImages": len(s.scap_image_ids or []) if s.scap_image_ids is not None else None,
        "scapStats": (s.scap_detail or {}).get("stats") if s.scap_detail else None,
    }


def scanner_run_summary(d: dict[str, Any] | None) -> dict[str, Any] | None:
    if not d:
        return None
    return {"status": d.get("status"), "findings": d.get("findings", 0), "durationMs": d.get("durationMs", 0),
            "error": d.get("error"), "version": d.get("version")}


def image_summary(img: Image) -> dict[str, Any]:
    return {
        "id": img.id,
        "ref": img.ref,
        "registry": img.registry_host,
        "repository": img.repository,
        "tag": img.tag,
        "tags": img.tags or [],
        "digest": img.digest,
        "score": img.score,
        "grade": img.grade or "?",
        "confidence": img.confidence,
        "counts": counts_of(img.counts),
        "fixable": counts_of(img.fixable),
        "scanners": {n: scanner_run_summary((img.scanners or {}).get(n)) for n in SCANNERS},
        "agreementIndex": img.agreement_index,
        "namespaces": img.namespaces or [],
        "workloads": img.workloads,
        "containers": img.containers,
        "running": img.running,
        "lastScannedAt": iso(img.last_scanned_at),
        "firstSeenAt": iso(img.first_seen_at),
        "lastSeenAt": iso(img.last_seen_at),
        "mirrored": img.mirrored,
        "mirrorRef": img.mirror_ref,
        # security review C2: the scanned mirror copy is digest-pinned (`…@sha256:`) and, when the
        # source digest is known, was checked against it (posture.mirror.Mirror.prepare)
        "mirrorDigestVerified": bool(img.mirrored and "@" in (img.mirror_ref or "") and img.digest),
        "warnings": img.warnings or [],
        "baseOs": f"{img.os_family} {img.os_name}".strip() if img.os_family else None,
        "provenance": getattr(img, "provenance", None),  # DESIGN §12, None until checked
        "stig": stig_brief(getattr(img, "stig", None)),  # DESIGN §14, None until evaluated
    }


def stig_brief(d: dict[str, Any] | None) -> dict[str, Any] | None:
    """`images.stig` -> ImageSummary.stig (camelCase, fixed keys)."""
    if not d:
        return None
    return {"status": d.get("status"), "score": d.get("score"), "benchmarks": int(d.get("benchmarks") or 0),
            "benchmarkIds": list(d.get("benchmarkIds") or []), "pass": int(d.get("pass") or 0),
            "fail": int(d.get("fail") or 0), "notapplicable": int(d.get("notapplicable") or 0),
            "notchecked": int(d.get("notchecked") or 0), "cat1Open": int(d.get("cat1Open") or 0),
            "cat2Open": int(d.get("cat2Open") or 0), "cat3Open": int(d.get("cat3Open") or 0),
            "fidelity": d.get("fidelity"), "os": d.get("os"), "evaluatedAt": d.get("evaluatedAt"),
            "error": d.get("error")}


def sla_due(first_seen: datetime | None, severity: str, sla: dict[str, int]) -> datetime | None:
    days = sla.get(severity)
    if first_seen is None or not days:
        return None
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=UTC)
    return first_seen + timedelta(days=days)


def finding_dict(c: ConsensusFindingRow, sla: dict[str, int] | None = None) -> dict[str, Any]:
    due = sla_due(c.first_seen_at, c.severity, sla or {})
    return {
        "vulnId": c.vuln_id,
        "severity": c.severity,
        "package": c.package,
        "installedVersion": c.installed_version,
        "fixedVersion": c.fixed_version,
        "pkgType": c.pkg_type,
        "scanners": c.scanners or [],
        "agreement": c.agreement,
        "perScanner": c.per_scanner or {},
        "cvss": c.cvss,
        "title": c.title,
        "url": c.url,
        "fixable": c.fixable,
        "controls": vuln_controls(c.fixable),
        "firstSeenAt": iso(c.first_seen_at),
        "slaDueAt": iso(due),
        "slaOverdue": bool(due and utcnow() > due),
    }


def image_scan_dict(r: ImageScan) -> dict[str, Any]:
    return {
        "id": r.id,
        "scanId": r.scan_id,
        "scanner": r.scanner,
        "status": r.status,
        "error": r.error,
        "version": r.version,
        "dbUpdatedAt": iso(r.db_updated_at),
        "startedAt": iso(r.started_at),
        "durationMs": r.duration_ms,
        "findings": r.findings_count,
        "scannedRef": r.scanned_ref,
        "rawSize": r.raw_size,
        "truncated": r.truncated,
        "hasRaw": r.raw_gz is not None,
    }


def container_ref(c: ContainerRow) -> dict[str, Any]:
    return {
        "namespace": c.namespace,
        "kind": c.workload_kind,
        "name": c.workload_name,
        "pod": c.pod,
        "container": c.container,
        "containerType": c.container_type,
        "image": c.image,
        "running": c.running,
        "pack": c.pack,
    }


async def scanner_rows(session: AsyncSession) -> dict[str, ScannerStatus]:
    return {r.name: r for r in (await session.execute(select(ScannerStatus))).scalars()}


def scanner_dict(name: str, row: ScannerStatus | None, enabled: bool) -> dict[str, Any]:
    return {
        "name": name,
        "enabled": enabled,
        "version": row.version if row else None,
        "dbUpdatedAt": iso(row.db_updated_at) if row else None,
        "healthy": bool(row.healthy) if row else False,
        "lastError": row.last_error if row else None,
        "lastRunAt": iso(row.last_run_at) if row else None,
    }


def freshness_warnings(rows: dict[str, ScannerStatus], enabled: dict[str, bool]) -> list[str]:
    out = []
    now = utcnow()
    for name in SCANNERS:
        if not enabled.get(name):
            continue
        row = rows.get(name)
        if row is None or row.db_updated_at is None:
            continue
        dt = row.db_updated_at if row.db_updated_at.tzinfo else row.db_updated_at.replace(tzinfo=UTC)
        age = now - dt
        if age > timedelta(hours=FRESHNESS_HOURS):
            days = age.days
            out.append(f"{name} database is {days} day{'s' if days != 1 else ''} old")
    return out


def page_params(page: int, page_size: int) -> tuple[int, int]:
    page = max(1, page)
    page_size = min(max(1, page_size), 500)
    return page, page_size
