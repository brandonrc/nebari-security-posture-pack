"""Build a ReportSnapshot from the database for one scan + scope (DESIGN §11)."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..controls import vuln_controls
from ..db.models import (
    ConsensusFindingRow,
    ContainerRow,
    Image,
    PostureResultRow,
    Scan,
    ScanSnapshot,
    WorkloadRow,
)
from ..db.models import ScannerStatus as ScannerStatusRow
from ..posture_checks import CHECKS, CHECKS_BY_ID
from ..scoring import SYSTEM_NAMESPACES
from ..severity import zero_counts
from ..views import SCANNERS, counts_of, sla_due
from .models import (
    CheckDefinition,
    FindingRecord,
    ImageRecord,
    NamespaceRecord,
    PostureResult,
    ReportSnapshot,
    ScanInfo,
    ScannerStatus,
    Scope,
    SystemInfo,
    TrendPoint,
    WorkloadRecord,
)

DEFAULT_SLA_EXTRA = {"negligible": 365, "unknown": 180}


def _scope(scope: Any) -> Scope:
    if scope is None:
        return Scope()
    if isinstance(scope, Scope):
        return scope
    if isinstance(scope, dict):
        return Scope.model_validate(scope)
    return Scope(kind=getattr(scope, "kind", "cluster"), name=getattr(scope, "name", None))


def _in_scope(scope: Scope, namespace: str, kind: str | None = None, name: str | None = None) -> bool:
    if scope.kind == "cluster" or not scope.name:
        return True
    if scope.kind == "namespace":
        return namespace == scope.name
    return f"{namespace}/{kind}/{name}" == scope.name


async def build_snapshot(session: AsyncSession, scan_id: int | None, scope: Any = None) -> ReportSnapshot:
    """`scan_id=None` -> latest completed scan. Raises LookupError when no such scan."""
    sc = _scope(scope)
    if scan_id is None:
        scan = (await session.execute(select(Scan).where(Scan.status == "done", Scan.inventory_complete.is_(True))
                                      .order_by(Scan.id.desc()).limit(1))).scalar_one_or_none()
    else:
        scan = await session.get(Scan, scan_id)
    if scan is None:
        raise LookupError("scan not found")
    settings = await app_settings.load(session)
    sla = {**settings.remediation_sla_days.model_dump(), **DEFAULT_SLA_EXTRA}

    containers = (await session.execute(select(ContainerRow).where(ContainerRow.scan_id == scan.id))).scalars().all()
    conts = [c for c in containers if _in_scope(sc, c.namespace, c.workload_kind, c.workload_name)]
    img_ids = {c.image_fk for c in conts if c.image_fk is not None}
    if not containers and sc.kind == "cluster":  # inventory pruned / unavailable: fall back to all images
        img_ids = {i for (i,) in (await session.execute(select(Image.id))).all()}
    imgs = (await session.execute(select(Image).where(Image.id.in_(img_ids or {0})))).scalars().all()

    per_img_wl: dict[int, set[str]] = defaultdict(set)
    per_img_ns: dict[int, set[str]] = defaultdict(set)
    per_img_pack: dict[int, set[str]] = defaultdict(set)
    per_img_cont: dict[int, int] = defaultdict(int)
    per_img_run: dict[int, int] = defaultdict(int)
    for c in conts:
        if c.image_fk is None:
            continue
        per_img_wl[c.image_fk].add(f"{c.namespace}/{c.workload_kind}/{c.workload_name}")
        per_img_ns[c.image_fk].add(c.namespace)
        if c.pack:
            per_img_pack[c.image_fk].add(c.pack)
        per_img_cont[c.image_fk] += 1
        per_img_run[c.image_fk] += int(c.running)

    images = []
    for i in imgs:
        nss = sorted(per_img_ns.get(i.id) or i.namespaces or [])
        images.append(ImageRecord(
            id=i.id, ref=i.ref, registry=i.registry_host, repository=i.repository, tag=i.tag or "",
            digest=i.digest or "", score=i.score, grade=i.grade or "?", counts=counts_of(i.counts),
            fixable=counts_of(i.fixable), namespaces=nss, workloads=sorted(per_img_wl.get(i.id, set())),
            packs=sorted(per_img_pack.get(i.id, set())), containers=per_img_cont.get(i.id, i.containers),
            running_containers=per_img_run.get(i.id, 0), running=i.running,
            os=f"{i.os_family or ''} {i.os_name or ''}".strip(),
            base_os=f"{i.os_family} {i.os_name}".strip() if i.os_family else None,
            scanner_status={n: (i.scanners or {}).get(n, {}).get("status", "skipped") for n in SCANNERS},
            scanner_versions={n: v for n in SCANNERS if (v := (i.scanners or {}).get(n, {}).get("version"))},
            agreement_index=i.agreement_index, last_scanned_at=i.last_scanned_at, mirrored=i.mirrored,
            warnings=i.warnings or [], system_namespace=bool(nss) and all(n in SYSTEM_NAMESPACES for n in nss),
        ))

    findings = []
    if imgs:
        rows = (await session.execute(select(ConsensusFindingRow).where(
            ConsensusFindingRow.image_id.in_([i.id for i in imgs])))).scalars().all()
        for f in rows:
            findings.append(FindingRecord(
                image_id=f.image_id, vuln_id=f.vuln_id, severity=f.severity, package=f.package,
                installed_version=f.installed_version or "", fixed_version=f.fixed_version, pkg_type=f.pkg_type or "",
                scanners=list(f.scanners or []), agreement=f.agreement, per_scanner=dict(f.per_scanner or {}),
                cvss=f.cvss, title=f.title or "", url=f.url or "", fixable=f.fixable, first_seen_at=f.first_seen_at,
                sla_due_at=sla_due(f.first_seen_at, f.severity, sla), controls=vuln_controls(f.fixable),
            ))

    refs = {i.id: i.ref for i in imgs}
    wrows = (await session.execute(select(WorkloadRow).where(WorkloadRow.scan_id == scan.id))).scalars().all()
    workloads = [WorkloadRecord(
        namespace=w.namespace, kind=w.kind, name=w.name, pack=w.pack, score=w.score, grade=w.grade,
        image_ids=list(w.image_ids or []), images=[refs[i] for i in (w.image_ids or []) if i in refs],
        containers=w.containers, running=w.running_containers > 0, system_namespace=w.system_namespace,
        posture={"passed": w.posture_passed, "failed": w.posture_failed}, counts=counts_of(w.counts),
    ) for w in wrows if _in_scope(sc, w.namespace, w.kind, w.name)]

    nsnaps = (await session.execute(select(ScanSnapshot).where(ScanSnapshot.scan_id == scan.id,
                                                               ScanSnapshot.level == "namespace"))).scalars().all()
    namespaces = [NamespaceRecord(
        name=s.key, pack=(s.data or {}).get("pack"), managed=bool((s.data or {}).get("managed")), score=s.score,
        grade=s.grade or "?", workloads=(s.data or {}).get("workloads", 0), images=(s.data or {}).get("images", 0),
        system_namespace=s.key in SYSTEM_NAMESPACES,
    ) for s in nsnaps if sc.kind != "namespace" or s.key == sc.name]
    if sc.kind == "workload":
        namespaces = [n for n in namespaces if any(w.namespace == n.name for w in workloads)]

    prows = (await session.execute(select(PostureResultRow).where(PostureResultRow.scan_id == scan.id))).scalars().all()
    posture = []
    passed: dict[str, int] = defaultdict(int)
    failed: dict[str, int] = defaultdict(int)
    for r in prows:
        if not _in_scope(sc, r.namespace, r.kind, r.name):
            continue
        chk = CHECKS_BY_ID.get(r.check_id)
        (failed if r.status == "fail" else passed)[r.check_id] += 1
        posture.append(PostureResult(
            check_id=r.check_id, status=r.status, title=chk.title if chk else r.check_id, namespace=r.namespace,
            kind=r.kind, name=r.name, container=r.container or None, detail=r.detail or "", severity=r.severity,
            controls=chk.controls if chk else [], remediation=chk.remediation if chk else "",
            system_namespace=r.system_namespace,
        ))
    checks = [CheckDefinition(id=c.id, title=c.title, severity=c.severity, category=c.category,
                              description=c.description, remediation=c.remediation, controls=c.controls,
                              passed=passed.get(c.id, 0), failed=failed.get(c.id, 0)) for c in CHECKS]

    srows = {r.name: r for r in (await session.execute(select(ScannerStatusRow))).scalars()}
    enabled = settings.scanners.model_dump()
    scanners = [ScannerStatus(
        name=n, enabled=enabled[n], version=(srows[n].version or "") if n in srows else "",
        db_updated_at=srows[n].db_updated_at if n in srows else None,
        healthy=bool(srows[n].healthy) if n in srows else False,
        last_error=srows[n].last_error if n in srows else None,
        last_run_at=srows[n].last_run_at if n in srows else None,
    ) for n in SCANNERS]

    trend_rows = (await session.execute(
        select(Scan, ScanSnapshot).join(ScanSnapshot, (ScanSnapshot.scan_id == Scan.id) & (ScanSnapshot.level == "cluster"))
        .where(Scan.status == "done", Scan.id <= scan.id).order_by(Scan.id.desc()).limit(30)
    )).all()
    trend = [TrendPoint(scan_id=s.id, finished_at=s.finished_at, score=snap.score, grade=snap.grade or "?",
                        critical=int(((snap.data or {}).get("counts") or {}).get("critical", 0)),
                        high=int(((snap.data or {}).get("counts") or {}).get("high", 0)))
             for s, snap in reversed(trend_rows)]

    now = datetime.now(UTC)
    running_ids = {i.id for i in imgs if i.running}
    counts, fixable = zero_counts(), zero_counts()
    overdue = {k: 0 for k in ("critical", "high", "medium", "low")}
    for f in findings:
        if f.image_id not in running_ids:
            continue
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.fixable:
            fixable[f.severity] = fixable.get(f.severity, 0) + 1
        if f.severity in overdue and f.sla_due_at and now > f.sla_due_at:
            overdue[f.severity] += 1
    summary = {
        "counts": counts, "fixable": fixable, "sla_overdue": overdue,
        "images_total": len(images), "images_scanned": sum(1 for i in images if i.score is not None),
        "images_failed": sum(1 for i in imgs if i.score is None and i.last_scanned_at is not None),
        "workloads": len(workloads), "namespaces": len({w.namespace for w in workloads}),
    }

    return ReportSnapshot(
        generated_at=now,
        system=SystemInfo(name=settings.system_name or "Nebari cluster", organization=settings.organization,
                          cluster_name=settings.system_name),
        scan=ScanInfo(id=scan.id, status=scan.status, trigger=scan.trigger, started_at=scan.started_at,
                      finished_at=scan.finished_at, requested_by=scan.requested_by or "", score=scan.score,
                      grade=scan.grade or "?", vuln_score=scan.vuln_score, posture_score=scan.posture_score),
        scope=sc, sla_days=sla, scanners=scanners, images=images, findings=findings, workloads=workloads,
        namespaces=namespaces, checks=checks, posture_results=posture, trend=trend, summary=summary,
    )
