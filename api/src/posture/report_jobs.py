"""Report jobs (DESIGN §11): the API and the scan worker only queue `reports` rows; the report
worker (posture.report_worker) claims them with a lease and calls `generate`, which renders with
`posture.reports.registry.generate`, writes `REPORTS_DIR/<id>.<ext>` and marks the row. Retention
(`prune`) keeps the newest N finished reports per type and caps their total bytes."""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import get_settings
from .db.models import Report
from .logs import get_logger
from .reports import registry
from .reports.registry import UnsupportedReport

log = get_logger(__name__)

# Format used for `reports.autoGenerate` (and when POST /reports omits `format`).
DEFAULT_FORMATS = {
    "poam": "xlsx",
    "stig-checklist": "cklb",
    "sar": "pdf",
    "oscal-ar": "json",
    "inventory": "xlsx",
    "vuln-export": "csv",
}
SCOPE_KINDS = ("cluster", "namespace", "workload")
POAM_VARIANTS = ("emass", "generic", "emass-legacy")


def reports_dir() -> Path:
    return Path(get_settings().reports_dir)


def report_dict(r: Report) -> dict[str, Any]:
    scope: dict[str, Any] = {"kind": r.scope_kind}
    if r.scope_kind != "cluster":
        scope["name"] = r.scope_name
    return {
        "id": str(r.id),
        "type": r.type,
        "format": r.format,
        "scope": scope,
        "scanId": r.scan_id,
        "status": r.status,
        "createdAt": r.created_at.isoformat() if r.created_at else None,
        "createdBy": r.created_by,
        "sizeBytes": r.size_bytes,
        "filename": r.filename,
        "contentType": r.content_type,
        "options": r.options or {},
        "error": r.error,
        "startedAt": r.started_at.isoformat() if r.started_at else None,
        "finishedAt": r.finished_at.isoformat() if r.finished_at else None,
        "attempts": r.attempts or 0,
    }


def validate_request(report_type: str, fmt: str | None, scope: dict[str, Any] | None,
                     options: dict[str, Any] | None) -> tuple[str, str, str | None]:
    """Returns (format, scope_kind, scope_name). Raises UnsupportedReport (-> 422)."""
    formats = registry.formats_for(report_type)  # raises UnsupportedReport for unknown types
    fmt = (fmt or DEFAULT_FORMATS.get(report_type) or formats[0]).lower()
    if fmt not in formats:
        raise UnsupportedReport(f"report type {report_type!r} does not support format {fmt!r} "
                                f"(supported: {', '.join(formats)})")
    scope = scope or {}
    kind = scope.get("kind") or "cluster"
    if kind not in SCOPE_KINDS:
        raise UnsupportedReport(f"unknown scope kind {kind!r}")
    name = scope.get("name") or None
    if kind != "cluster" and not name:
        raise UnsupportedReport(f"scope kind {kind!r} requires a name")
    if kind == "workload" and name and name.count("/") != 2:
        raise UnsupportedReport("workload scope name must be '<namespace>/<kind>/<name>'")
    variant = (options or {}).get("poamVariant")
    if variant is not None and variant not in POAM_VARIANTS:
        raise UnsupportedReport(f"unknown poamVariant {variant!r}")
    return fmt, kind, (name if kind != "cluster" else None)


async def create_row(session: AsyncSession, *, report_type: str, fmt: str, scope_kind: str,
                     scope_name: str | None, scan_id: int, options: dict[str, Any] | None,
                     created_by: str | None) -> Report:
    row = Report(id=uuid.uuid4(), type=report_type, format=fmt, scope_kind=scope_kind, scope_name=scope_name,
                 scan_id=scan_id, status="queued", created_by=created_by, options=dict(options or {}))
    session.add(row)
    await session.flush()
    await session.refresh(row)
    return row


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _unlink(path: str | None) -> None:
    if not path:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except OSError as e:  # never fail a request because a stale file could not be removed
        log.warning("report.unlink_failed", path=path, error=str(e))


def _fail_message(e: BaseException) -> str:
    return (str(e).splitlines() or [type(e).__name__])[0][:2000] or type(e).__name__


async def _mark(sm: async_sessionmaker[AsyncSession], rid: uuid.UUID, worker_id: str | None,
                **values: Any) -> bool:
    """Update a running row we still own (a lease that expired and was re-claimed is not ours)."""
    stmt = update(Report).where(Report.id == rid, Report.status == "running")
    if worker_id is not None:
        stmt = stmt.where(Report.worker_id == worker_id)
    async with sm() as s, s.begin():
        res = await s.execute(stmt.values(**values))
        return bool(res.rowcount)


async def mark_failed(sm: async_sessionmaker[AsyncSession], report_id: uuid.UUID | str, error: str,
                      worker_id: str | None = None) -> bool:
    return await _mark(sm, uuid.UUID(str(report_id)), worker_id, status="failed", error=error[:2000],
                       finished_at=datetime.now(UTC), leased_until=None)


async def generate(sm: async_sessionmaker[AsyncSession], report_id: uuid.UUID | str,
                   worker_id: str | None = None) -> str:
    """Generate one report the caller has claimed (status `running`): build the snapshot, render,
    write `REPORTS_DIR/<id>.<ext>` (temp file + fsync + rename) and mark the row done or failed.
    Never raises for generator / IO errors; returns the final status. Runs in the report worker
    (in a child process per report by default, see posture.report_worker)."""
    from .reports.snapshot import build_snapshot  # heavy import, keep module import light

    rid = uuid.UUID(str(report_id))
    async with sm() as s:
        row = await s.get(Report, rid)
        if row is None:
            return "missing"
        if row.status != "running" or (worker_id is not None and row.worker_id != worker_id):
            return row.status
        rtype, fmt, scan_id = row.type, row.format, row.scan_id
        scope = {"kind": row.scope_kind, "name": row.scope_name}
        options = dict(row.options or {})
    started = datetime.now(UTC)
    path = reports_dir() / f"{rid}.{fmt}"
    try:
        async with sm() as s:
            snapshot = await build_snapshot(s, scan_id, scope)
            if rtype == "oscal-ssp":  # DESIGN §13: latest control evidence engine run
                from .controls_engine.reporting import attach

                await attach(s, snapshot)
        rep = await asyncio.to_thread(registry.generate, rtype, fmt, snapshot, options)
        del snapshot
        size = len(rep.content)
        await asyncio.to_thread(_write_atomic, path, rep.content)
    except Exception as e:  # noqa: BLE001  (ReportDependencyMissing, LookupError, IO errors, generator bugs)
        msg = _fail_message(e)
        if not isinstance(e, (registry.ReportDependencyMissing, LookupError, OSError, UnsupportedReport)):
            log.exception("report.failed", report_id=str(rid), type=rtype, format=fmt)
        else:
            log.warning("report.failed", report_id=str(rid), type=rtype, format=fmt, error=msg)
        await mark_failed(sm, rid, msg, worker_id)
        return "failed"
    ok = await _mark(sm, rid, worker_id, status="done", filename=rep.filename, content_type=rep.content_type,
                     size_bytes=size, path=str(path), error=None, finished_at=datetime.now(UTC), leased_until=None)
    if not ok:  # deleted (or re-claimed after our lease expired) while generating
        async with sm() as s:
            current = await s.get(Report, rid)
        if current is None or current.path != str(path):
            _unlink(str(path))
        return "missing" if current is None else current.status
    log.info("report.done", report_id=str(rid), type=rtype, format=fmt, size=size,
             duration_ms=int((datetime.now(UTC) - started).total_seconds() * 1000))
    return "done"


async def enqueue_auto(sm: async_sessionmaker[AsyncSession], scan_id: int, types: list[str]) -> list[str]:
    """Settings `reports.autoGenerate`: queue one cluster-scope report per type in its default
    format for the report worker. Never raises; returns the queued ids."""
    ids: list[str] = []
    for rtype in types:
        try:
            fmt, kind, name = validate_request(rtype, None, None, None)
            async with sm() as s, s.begin():
                row = await create_row(s, report_type=rtype, fmt=fmt, scope_kind=kind, scope_name=name,
                                       scan_id=scan_id, options={}, created_by="auto")
                ids.append(str(row.id))
        except Exception:  # noqa: BLE001
            log.exception("report.auto_enqueue_failed", scan_id=scan_id, type=rtype)
    log.info("report.auto_queued", scan_id=scan_id, count=len(ids))
    return ids


async def run_report(sm: async_sessionmaker[AsyncSession], report_id: uuid.UUID | str) -> str:
    """Claim and generate one queued report in this process (tests, tooling). Production runs
    go through posture.report_worker."""
    rid = uuid.UUID(str(report_id))
    async with sm() as s, s.begin():
        row = await s.get(Report, rid, with_for_update=True)
        if row is None or row.status not in ("queued", "running"):
            return row.status if row else "missing"
        row.status, row.worker_id = "running", None
        row.started_at = row.started_at or datetime.now(UTC)
    status = await generate(sm, rid)
    await prune(sm)
    return status


async def prune(sm: async_sessionmaker[AsyncSession], report_type: str | None = None, keep: int | None = None,
                max_total_bytes: int | None = None) -> int:
    """Retention, oldest first: keep the newest `keep` finished reports per type
    (REPORTS_RETENTION_PER_TYPE, 20) and cap the bytes of finished reports at
    REPORTS_MAX_TOTAL_BYTES (2 GiB; the newest report always stays). Deletes rows and files."""
    st = get_settings()
    keep = st.report_keep_per_type if keep is None else keep
    cap = st.report_max_total_bytes if max_total_bytes is None else max_total_bytes
    finished = ("done", "failed")
    async with sm() as s, s.begin():
        rows = (await s.execute(
            select(Report.id, Report.type, Report.size_bytes, Report.path)
            .where(Report.status.in_(finished)).order_by(Report.created_at.desc(), Report.id.desc())
        )).all()
        doomed: dict[uuid.UUID, str | None] = {}
        per_type: dict[str, int] = {}
        for rid, rtype, _, path in rows:
            per_type[rtype] = per_type.get(rtype, 0) + 1
            if (report_type is None or rtype == report_type) and per_type[rtype] > max(keep, 0):
                doomed[rid] = path
        if cap and cap > 0:
            total = 0
            for n, (rid, _, size, path) in enumerate(rows):
                if rid in doomed:
                    continue
                total += size or 0
                if total > cap and n > 0:
                    doomed[rid] = path
        if doomed:
            await s.execute(delete(Report).where(Report.id.in_(list(doomed))))
    for p in doomed.values():
        _unlink(p)
    if doomed:
        log.info("report.pruned", deleted=len(doomed), keep_per_type=keep, max_total_bytes=cap)
    return len(doomed)


async def fail_interrupted(sm: async_sessionmaker[AsyncSession], older_than: timedelta = timedelta(minutes=15)) -> None:
    """Deprecated: the report worker requeues expired leases (posture.report_worker). Kept for
    callers of the old API; marks only rows without a lease."""
    cutoff = datetime.now(UTC) - older_than
    async with sm() as s, s.begin():
        await s.execute(update(Report).where(Report.status.in_(("queued", "running")), Report.created_at < cutoff,
                                             Report.leased_until.is_(None), Report.worker_id.is_(None))
                        .values(status="failed", error="interrupted (process restarted)"))


def delete_file(path: str | None) -> None:
    _unlink(path)
