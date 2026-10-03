"""Report jobs (DESIGN §11): queue a `reports` row, generate it off the event loop with
`posture.reports.registry.generate`, store the bytes under `REPORTS_DIR/<id>.<ext>` and apply
retention (last N per type). Used by the API (BackgroundTask) and the worker (auto-generate
after a completed scan)."""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
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


async def run_report(sm: async_sessionmaker[AsyncSession], report_id: uuid.UUID | str) -> str:
    """Generate one queued report. Never raises; returns the final status."""
    from .reports.snapshot import build_snapshot  # heavy import, keep module import light

    rid = uuid.UUID(str(report_id))
    async with sm() as s, s.begin():
        row = await s.get(Report, rid, with_for_update=True)
        if row is None or row.status not in ("queued", "running"):
            return row.status if row else "missing"
        row.status = "running"
        rtype, fmt, scan_id = row.type, row.format, row.scan_id
        scope = {"kind": row.scope_kind, "name": row.scope_name}
        options = dict(row.options or {})
    started = datetime.now(UTC)
    try:
        async with sm() as s:
            snapshot = await build_snapshot(s, scan_id, scope)
            if rtype == "oscal-ssp":  # DESIGN §13: latest control evidence engine run
                from .controls_engine.reporting import attach

                await attach(s, snapshot)
        rep = await asyncio.to_thread(registry.generate, rtype, fmt, snapshot, options)
        path = reports_dir() / f"{rid}.{fmt}"
        await asyncio.to_thread(_write_atomic, path, rep.content)
    except Exception as e:  # noqa: BLE001  (ReportDependencyMissing, LookupError, IO errors, generator bugs)
        msg = (str(e).splitlines() or [type(e).__name__])[0][:2000] or type(e).__name__
        if not isinstance(e, (registry.ReportDependencyMissing, LookupError, OSError, UnsupportedReport)):
            log.exception("report.failed", report_id=str(rid), type=rtype, format=fmt)
        else:
            log.warning("report.failed", report_id=str(rid), type=rtype, format=fmt, error=msg)
        async with sm() as s, s.begin():
            await s.execute(update(Report).where(Report.id == rid).values(status="failed", error=msg))
        return "failed"
    async with sm() as s, s.begin():
        row = await s.get(Report, rid, with_for_update=True)
        if row is None:  # deleted while generating
            _unlink(str(path))
            return "missing"
        row.status, row.filename, row.content_type = "done", rep.filename, rep.content_type
        row.size_bytes, row.path, row.error = len(rep.content), str(path), None
    log.info("report.done", report_id=str(rid), type=rtype, format=fmt, size=len(rep.content),
             duration_ms=int((datetime.now(UTC) - started).total_seconds() * 1000))
    await prune(sm, rtype)
    return "done"


async def prune(sm: async_sessionmaker[AsyncSession], report_type: str, keep: int | None = None) -> int:
    """Keep the newest `keep` finished reports of a type; delete older rows and files."""
    keep = get_settings().reports_keep_per_type if keep is None else keep
    async with sm() as s, s.begin():
        old = (await s.execute(
            select(Report).where(Report.type == report_type, Report.status.in_(("done", "failed")))
            .order_by(Report.created_at.desc(), Report.id.desc()).offset(max(keep, 0))
        )).scalars().all()
        paths = [r.path for r in old]
        for r in old:
            await s.delete(r)
    for p in paths:
        _unlink(p)
    if old:
        log.info("report.pruned", type=report_type, deleted=len(old))
    return len(old)


async def fail_interrupted(sm: async_sessionmaker[AsyncSession], older_than: timedelta = timedelta(minutes=15)) -> None:
    """Mark reports left queued/running by a dead process as failed."""
    cutoff = datetime.now(UTC) - older_than
    async with sm() as s, s.begin():
        await s.execute(update(Report).where(Report.status.in_(("queued", "running")), Report.created_at < cutoff)
                        .values(status="failed", error="interrupted (process restarted)"))


def delete_file(path: str | None) -> None:
    _unlink(path)
