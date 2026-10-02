"""Scan worker: `python -m posture.worker` (DESIGN §4).

* Postgres-as-queue: `scans` rows with status `queued`, claimed with
  `SELECT ... FOR UPDATE SKIP LOCKED`.
* APScheduler: periodic scheduled scans, grype DB updates, scanner status refresh.
* Pipeline: inventory -> unique images -> mirror -> 3 scanners concurrently per image
  (N images in parallel) -> correlate -> score -> persist -> posture -> aggregates.
* A scanner failure never fails the scan; only an inventory failure does.
"""

from __future__ import annotations

import asyncio
import gzip
import os
import signal
import socket
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import app_settings, report_jobs
from .aggregate import ImageInfo, aggregate
from .analysis import analyze
from .config import Settings, get_settings
from .db.models import (
    ConsensusFindingRow,
    ContainerRow,
    FindingRow,
    Image,
    ImageScan,
    PostureResultRow,
    Scan,
    ScannerStatus,
    ScanSnapshot,
    WorkerHeartbeat,
    WorkloadRow,
)
from .images import identify_image, parse_image_ref
from .inventory import collect
from .inventory_model import InventorySnapshot
from .logs import get_logger, setup_logging
from .mirror import Mirror, ScanTarget
from .posture_checks import evaluate_inventory
from .scanners import ClairScanner, GrypeScanner, Scanner, ScanResult, TrivyScanner
from .scanners.base import RAW_MAX_BYTES

log = get_logger("posture.worker")

LOG_LINES_KEPT = 200
KEEP_INVENTORY_SCANS = 10


def now() -> datetime:
    return datetime.now(UTC)


def compress_raw(raw: str | None) -> tuple[bytes | None, int, bool]:
    if raw is None:
        return None, 0, False
    data = raw.encode("utf-8", "replace")
    size = len(data)
    truncated = size > RAW_MAX_BYTES
    if truncated:
        data = data[:RAW_MAX_BYTES]
    return gzip.compress(data, compresslevel=6), size, truncated


def build_scanners(s: Settings) -> dict[str, Scanner]:
    docker_config = os.environ.get("DOCKER_CONFIG")
    return {
        "trivy": TrivyScanner(s.trivy_server_url, s.trivy_bin, s.cache_dir, docker_config),
        "grype": GrypeScanner(s.grype_bin, s.cache_dir, docker_config),
        "clair": ClairScanner(s.clair_url, s.clairctl_bin, s.cache_dir, s.mirror_registry, docker_config),
    }


@dataclass
class ScanContext:
    scan_id: int
    settings: app_settings.AppSettings
    enabled: list[str]
    cancelled: bool = False
    log_lines: deque = field(default_factory=lambda: deque(maxlen=LOG_LINES_KEPT))
    per_scanner: dict[str, dict[str, int]] = field(default_factory=dict)
    done: int = 0
    failed: int = 0
    dirty: bool = True

    def add_log(self, msg: str) -> None:
        self.log_lines.append(f"{now().strftime('%Y-%m-%dT%H:%M:%SZ')} {msg}")
        self.dirty = True


class Worker:
    def __init__(
        self,
        settings: Settings,
        sessionmaker: async_sessionmaker[AsyncSession],
        scanners: dict[str, Scanner] | None = None,
        inventory_fn: Callable[[list[str]], Awaitable[InventorySnapshot]] | None = None,
        mirror: Mirror | Any | None = None,
    ):
        self.s = settings
        self.sm = sessionmaker
        self.scanners = scanners if scanners is not None else build_scanners(settings)
        self.inventory_fn = inventory_fn or collect
        self.mirror = mirror if mirror is not None else Mirror(settings)
        self.last_loop_beat = time.monotonic()
        self.hostname = socket.gethostname()
        self._stop = asyncio.Event()
        self.scheduler = None
        self._interval_hours: float | None = None
        self._versions: dict[str, str] = {}

    # ------------------------------------------------------------------ queue
    async def enqueue(self, trigger: str = "scheduled", requested_by: str | None = None, force: bool = False) -> int | None:
        async with self.sm() as s, s.begin():
            active = await s.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(("queued", "running")),
                                                                                  Scan.target_image_ids.is_(None)))
            if active:
                return None
            scan = Scan(trigger=trigger, status="queued", requested_by=requested_by or "scheduler", force=force,
                        per_scanner={}, log=[])
            s.add(scan)
            await s.flush()
            log.info("scan.enqueued", scan_id=scan.id, trigger=trigger)
            return scan.id

    async def claim_next(self) -> int | None:
        async with self.sm() as s, s.begin():
            scan = (await s.execute(
                select(Scan).where(Scan.status == "queued").order_by(Scan.id).limit(1).with_for_update(skip_locked=True)
            )).scalar_one_or_none()
            if scan is None:
                return None
            scan.status = "running"
            scan.started_at = now()
            scan.heartbeat_at = now()
            return scan.id

    async def recover_stale(self) -> None:
        """Single-replica worker: anything `running` at startup was orphaned by a restart."""
        async with self.sm() as s, s.begin():
            res = await s.execute(
                update(Scan).where(Scan.status == "running")
                .values(status="failed", finished_at=now(), error="worker restarted during scan")
            )
            if res.rowcount:
                log.warning("scan.recovered_stale", count=res.rowcount)

    # ------------------------------------------------------------ scanners
    async def refresh_scanner_status(self, enabled: list[str] | None = None) -> None:
        async def one(name: str, sc: Scanner) -> dict[str, Any]:
            info: dict[str, Any] = {"name": name, "healthy": True, "last_error": None}
            try:
                info["version"] = await asyncio.wait_for(sc.version(), 60)
            except Exception as e:  # noqa: BLE001
                info["version"] = None
                info["healthy"], info["last_error"] = False, f"version check failed: {e}"
            try:
                info["db_updated_at"] = await asyncio.wait_for(sc.db_updated_at(), 60)
            except Exception:  # noqa: BLE001
                info["db_updated_at"] = None
            hc = getattr(sc, "healthy", None)
            if callable(hc):
                try:
                    ok, err = await asyncio.wait_for(hc(), 15)
                    if not ok:
                        info["healthy"], info["last_error"] = False, err
                except Exception as e:  # noqa: BLE001
                    info["healthy"], info["last_error"] = False, str(e)
            if name == "grype" and info.get("db_updated_at") is None:
                info["healthy"], info["last_error"] = False, info["last_error"] or "grype database missing"
            return info

        names = enabled if enabled is not None else list(self.scanners)
        infos = await asyncio.gather(*(one(n, self.scanners[n]) for n in names if n in self.scanners))
        for info in infos:
            if info.get("version"):
                self._versions[info["name"]] = info["version"]
        async with self.sm() as s, s.begin():
            for info in infos:
                row = await s.get(ScannerStatus, info["name"])
                if row is None:
                    row = ScannerStatus(name=info["name"])
                    s.add(row)
                row.version = info.get("version") or row.version
                row.db_updated_at = info.get("db_updated_at") or row.db_updated_at
                row.healthy = bool(info["healthy"])
                row.last_error = info["last_error"]
                row.updated_at = now()

    async def _record_scanner_run(self, results: list[ScanResult]) -> None:
        async with self.sm() as s, s.begin():
            for r in results:
                row = await s.get(ScannerStatus, r.scanner)
                if row is None:
                    row = ScannerStatus(name=r.scanner, healthy=r.ok)
                    s.add(row)
                row.last_run_at = now()
                if r.version:
                    row.version = r.version
                if r.db_updated_at:
                    row.db_updated_at = r.db_updated_at
                if r.ok:
                    row.healthy = True
                    row.last_error = None
                else:
                    row.last_error = r.error

    async def update_grype_db(self) -> None:
        grype = self.scanners.get("grype")
        if not isinstance(grype, GrypeScanner):
            return
        log.info("grype.db_update.start")
        ok, err = await grype.update_db()
        if ok:
            log.info("grype.db_update.done")
        else:
            log.error("grype.db_update.failed", error=err)
        await self.refresh_scanner_status(["grype"])

    # ------------------------------------------------------------ pipeline
    async def _flush_progress(self, ctx: ScanContext) -> None:
        async with self.sm() as s, s.begin():
            scan = await s.get(Scan, ctx.scan_id, with_for_update=True)
            if scan is None:
                ctx.cancelled = True
                return
            if scan.status == "cancelled":
                ctx.cancelled = True
            scan.images_done = ctx.done
            scan.images_failed = ctx.failed
            scan.per_scanner = {k: dict(v) for k, v in ctx.per_scanner.items()}
            scan.log = list(ctx.log_lines)
            scan.heartbeat_at = now()
            ctx.dirty = False

    async def _progress_loop(self, ctx: ScanContext) -> None:
        while True:
            await asyncio.sleep(3)
            try:
                await self._flush_progress(ctx)
            except Exception:  # noqa: BLE001
                log.exception("scan.progress_flush_failed", scan_id=ctx.scan_id)

    async def run_scan(self, scan_id: int) -> None:
        async with self.sm() as s:
            scan = await s.get(Scan, scan_id)
            settings = await app_settings.load(s, self.s)
            force = scan.force
            target_ids = list(scan.target_image_ids or [])
            target_ns = list(scan.target_namespaces or [])
        enabled = [n for n in ("trivy", "grype", "clair") if getattr(settings.scanners, n) and n in self.scanners]
        ctx = ScanContext(scan_id, settings, enabled)
        ctx.per_scanner = {n: {"ok": 0, "error": 0} for n in enabled}
        ctx.add_log(f"scan started (scanners: {', '.join(enabled) or 'none'})")
        log.info("scan.started", scan_id=scan_id, scanners=",".join(enabled), force=force)
        progress = asyncio.create_task(self._progress_loop(ctx))
        completed = False
        try:
            try:
                inv = await self.inventory_fn(settings.excluded_namespaces)
            except Exception as e:  # noqa: BLE001
                log.exception("scan.inventory_failed", scan_id=scan_id)
                ctx.add_log(f"inventory failed: {e}")
                await self._finish(ctx, "failed", error=f"inventory failed: {e}")
                return
            for err in inv.errors:
                ctx.add_log(f"inventory warning: {err}")
            ctx.add_log(f"inventory: {len(inv.containers)} containers in {len(inv.namespaces)} namespaces")
            key_to_id = await self._upsert_images(inv)
            to_scan = await self._select_images(key_to_id, inv, target_ids, target_ns, force, settings)
            async with self.sm() as s, s.begin():
                await s.execute(update(Scan).where(Scan.id == scan_id).values(images_total=len(to_scan)))
            ctx.add_log(f"{len(to_scan)} image(s) to scan, {len(key_to_id)} unique image(s) in inventory")
            if enabled:
                await self.refresh_scanner_status(enabled)
            sem = asyncio.Semaphore(max(1, settings.parallelism))

            async def guarded(image_id: int) -> None:
                async with sem:
                    if ctx.cancelled:
                        return
                    try:
                        await self._process_image(ctx, image_id)
                    except Exception as e:  # noqa: BLE001  (never fail the scan for one image)
                        log.exception("image.failed", scan_id=scan_id, image_id=image_id)
                        ctx.failed += 1
                        ctx.done += 1
                        ctx.add_log(f"image {image_id}: internal error {e}")

            await asyncio.gather(*(guarded(i) for i in to_scan))
            await self._flush_progress(ctx)
            if ctx.cancelled:
                ctx.add_log("scan cancelled")
                await self._finish(ctx, "cancelled")
                return
            await self._persist_snapshot(ctx, inv, key_to_id)
            await self._finish(ctx, "done")
            completed = True
        except asyncio.CancelledError:
            await self._finish(ctx, "failed", error="worker shutting down")
            raise
        except Exception as e:  # noqa: BLE001
            log.exception("scan.failed", scan_id=scan_id)
            await self._finish(ctx, "failed", error=str(e)[:2000])
        finally:
            progress.cancel()
        if completed and settings.reports.auto_generate:
            await self.auto_generate_reports(scan_id, settings.reports.auto_generate)

    async def auto_generate_reports(self, scan_id: int, types: list[str]) -> list[str]:
        """Settings `reports.autoGenerate`: one cluster-scope report per type in its default format.
        Best effort: a failing report is recorded as a failed row and never fails the scan."""
        statuses: list[str] = []
        for rtype in types:
            try:
                fmt, kind, name = report_jobs.validate_request(rtype, None, None, None)
                async with self.sm() as s, s.begin():
                    row = await report_jobs.create_row(s, report_type=rtype, fmt=fmt, scope_kind=kind,
                                                       scope_name=name, scan_id=scan_id, options={},
                                                       created_by="auto")
                    rid = row.id
                status = await report_jobs.run_report(self.sm, rid)
            except Exception:  # noqa: BLE001
                log.exception("report.auto_failed", scan_id=scan_id, type=rtype)
                status = "failed"
            statuses.append(status)
            log.info("report.auto", scan_id=scan_id, type=rtype, status=status)
        return statuses

    async def _finish(self, ctx: ScanContext, status: str, error: str | None = None) -> None:
        async with self.sm() as s, s.begin():
            scan = await s.get(Scan, ctx.scan_id, with_for_update=True)
            if scan is None:
                return
            if scan.status == "cancelled" and status != "cancelled":
                status = "cancelled"
            scan.status = status
            scan.finished_at = now()
            scan.images_done = ctx.done
            scan.images_failed = ctx.failed
            scan.per_scanner = {k: dict(v) for k, v in ctx.per_scanner.items()}
            if error:
                scan.error = error
                ctx.add_log(f"error: {error}")
            ctx.add_log(f"scan {status}")
            scan.log = list(ctx.log_lines)
        log.info("scan.finished", scan_id=ctx.scan_id, status=status, images_done=ctx.done, images_failed=ctx.failed)

    async def _upsert_images(self, inv: InventorySnapshot) -> dict[str, int]:
        # containers without an imageID (not started yet) borrow the digest key of a
        # sibling container that runs the same spec image.
        by_spec: dict[str, str] = {}
        idents = []
        for c in inv.containers:
            ident = identify_image(c.image, c.image_id)
            idents.append(ident)
            if c.image_id and "@" in ident.key:
                try:
                    by_spec.setdefault(parse_image_ref(c.image).tagged, ident.key)
                except ValueError:
                    pass
        info: dict[str, dict[str, Any]] = {}
        for c, ident in zip(inv.containers, idents, strict=True):
            key = ident.key
            if not c.image_id and "@" not in key:
                key = by_spec.get(key, key)
            c.image_key = key
            entry = info.setdefault(key, {"ident": ident, "namespaces": set(), "workloads": set(), "containers": 0,
                                          "running": False, "tags": set()})
            if ident.ref.tag:
                entry["tags"].add(ident.ref.tag)
            if entry["ident"].ref.tag is None and ident.ref.tag:
                entry["ident"] = ident
            entry["namespaces"].add(c.namespace)
            entry["workloads"].add((c.namespace, c.workload_kind, c.workload_name))
            entry["containers"] += 1
            entry["running"] = entry["running"] or c.running
        ts = now()
        key_to_id: dict[str, int] = {}
        async with self.sm() as s, s.begin():
            existing = {i.key: i for i in (await s.execute(select(Image).where(Image.key.in_(list(info) or [""])))).scalars()}
            await s.execute(update(Image).values(running=False))
            for key, e in info.items():
                ref = e["ident"].ref
                img = existing.get(key)
                if img is None:
                    img = Image(key=key, registry_host=ref.registry, repository=ref.repository, digest=ref.digest,
                                counts={}, fixable={}, scanners={}, warnings=[], tags=[], namespaces=[], first_seen_at=ts)
                    s.add(img)
                img.ref = ref.display
                img.tag = ref.tag or img.tag
                img.tags = sorted(set(img.tags or []) | e["tags"])
                img.namespaces = sorted(e["namespaces"])
                img.workloads = len(e["workloads"])
                img.containers = e["containers"]
                img.running = e["running"]
                img.last_seen_at = ts
                base = [w for w in (img.warnings or []) if not w.startswith(("imageID", "unparseable"))]
                img.warnings = sorted(set(base) | set(e["ident"].warnings))
            await s.flush()
            for key in info:
                key_to_id[key] = (existing.get(key) or (await s.execute(select(Image).where(Image.key == key))).scalar_one()).id
        return key_to_id

    async def _select_images(self, key_to_id: dict[str, int], inv: InventorySnapshot, target_ids: list[int],
                             target_ns: list[str], force: bool, settings: app_settings.AppSettings) -> list[int]:
        if target_ids:
            candidates = {int(i) for i in target_ids}
        elif target_ns:
            nsset = set(target_ns)
            candidates = {key_to_id[c.image_key] for c in inv.containers if c.namespace in nsset and c.image_key in key_to_id}
        else:
            candidates = set(key_to_id.values())
        if not candidates:
            return []
        async with self.sm() as s:
            imgs = (await s.execute(select(Image).where(Image.id.in_(candidates)))).scalars().all()
        cutoff = now() - timedelta(hours=settings.rescan_after_hours)
        out = []
        for img in imgs:
            fresh = img.last_scanned_at is not None and img.last_scanned_at > cutoff and img.score is not None
            if force or target_ids or not fresh:
                out.append(img.id)
        return sorted(out)

    async def _scan_one(self, name: str, target: ScanTarget) -> ScanResult:
        result = await self._scan_one_raw(name, target)
        if not result.version:
            result.version = self._versions.get(name)
        return result

    async def _scan_one_raw(self, name: str, target: ScanTarget) -> ScanResult:
        scanner = self.scanners[name]
        try:
            return await asyncio.wait_for(
                scanner.scan(target.ref, insecure=target.insecure, timeout=self.s.scan_timeout_seconds),
                self.s.scan_timeout_seconds + 30,
            )
        except (TimeoutError, asyncio.TimeoutError):
            return ScanResult(name, "timeout", error=f"timed out after {self.s.scan_timeout_seconds}s")
        except Exception as e:  # noqa: BLE001
            return ScanResult(name, "error", error=f"adapter error: {e}")

    async def _process_image(self, ctx: ScanContext, image_id: int) -> None:
        async with self.sm() as s:
            img = await s.get(Image, image_id)
            if img is None:
                ctx.done += 1
                return
            ref = parse_image_ref(img.key)
            if img.tag and not ref.tag:
                ref = type(ref)(ref.registry, ref.repository, img.tag, ref.digest)
            display = img.ref
        started = now()
        target = await self.mirror.prepare(ref)
        for w in target.warnings:
            ctx.add_log(f"{display}: {w}")
        results = await asyncio.gather(*(self._scan_one(n, target) for n in ctx.enabled)) if ctx.enabled else []
        analysis = analyze(list(results))
        for r in results:
            bucket = ctx.per_scanner.setdefault(r.scanner, {"ok": 0, "error": 0})
            bucket["ok" if r.ok else "error"] += 1
            if not r.ok:
                ctx.add_log(f"{display}: {r.scanner} {r.status}: {(r.error or '')[:200]}")
        await self._persist_image(ctx, image_id, target, list(results), analysis, started)
        await self._record_scanner_run(list(results))
        ctx.done += 1
        if analysis.score.score is None:
            ctx.failed += 1
        ctx.add_log(f"{display}: score {analysis.score.score} ({analysis.score.grade}), "
                    f"{len(analysis.consensus)} findings, scanners ok: {','.join(analysis.succeeded) or 'none'}")
        log.info("image.scanned", scan_id=ctx.scan_id, image_id=image_id, ref=display, score=analysis.score.score,
                 findings=len(analysis.consensus), ok=",".join(analysis.succeeded))

    async def _persist_image(self, ctx: ScanContext, image_id: int, target: ScanTarget, results: list[ScanResult],
                             analysis, started: datetime) -> None:
        ts = now()
        async with self.sm() as s, s.begin():
            img = await s.get(Image, image_id, with_for_update=True)
            for r in results:
                raw_gz, raw_size, truncated = compress_raw(r.raw)
                isc = ImageScan(scan_id=ctx.scan_id, image_id=image_id, scanner=r.scanner, status=r.status,
                                error=r.error, version=r.version, db_updated_at=r.db_updated_at, started_at=started,
                                duration_ms=r.duration_ms, findings_count=len(r.findings), scanned_ref=target.ref,
                                raw_gz=raw_gz, raw_size=raw_size, truncated=truncated)
                s.add(isc)
                await s.flush()
                if r.ok:
                    await s.execute(delete(FindingRow).where(FindingRow.image_id == image_id,
                                                             FindingRow.scanner == r.scanner))
                    if r.findings:
                        await s.execute(FindingRow.__table__.insert(), [
                            {"image_scan_id": isc.id, "image_id": image_id, "scanner": r.scanner,
                             "vuln_id": f.vuln_id[:128], "severity": f.severity, "package": f.package,
                             "installed_version": f.installed_version, "fixed_version": f.fixed_version,
                             "pkg_type": (f.pkg_type or "")[:64] or None, "cvss": f.cvss, "title": f.title, "url": f.url}
                            for f in r.findings])
            if analysis.succeeded:
                prev = {(c.vuln_id, c.package): c.first_seen_at for c in (await s.execute(
                    select(ConsensusFindingRow).where(ConsensusFindingRow.image_id == image_id))).scalars()}
                await s.execute(delete(ConsensusFindingRow).where(ConsensusFindingRow.image_id == image_id))
                rows = []
                seen: set[tuple[str, str]] = set()
                for c in analysis.consensus:
                    k = (c.vuln_id[:128], c.package)
                    if k in seen:
                        continue
                    seen.add(k)
                    rows.append({
                        "image_id": image_id, "scan_id": ctx.scan_id, "vuln_id": k[0], "package": c.package,
                        "installed_version": c.installed_version, "fixed_version": c.fixed_version,
                        "pkg_type": (c.pkg_type or "")[:64] or None, "severity": c.severity, "scanners": c.scanners,
                        "per_scanner": c.per_scanner, "agreement": c.agreement, "cvss": c.cvss, "title": c.title,
                        "url": c.url, "fixable": c.fixable, "first_seen_at": prev.get(k, ts), "last_seen_at": ts,
                    })
                if rows:
                    await s.execute(ConsensusFindingRow.__table__.insert(), rows)
                img.counts = analysis.counts
                img.fixable = analysis.fixable
                img.agreement_index = analysis.agreement_index
                img.os_family = analysis.os_family or img.os_family
                img.os_name = analysis.os_name or img.os_name
            img.score = analysis.score.score
            img.grade = analysis.score.grade
            img.penalty = analysis.score.penalty
            img.confidence = analysis.score.confidence
            img.scanners = analysis.scanners
            img.mirrored = target.mirrored
            img.mirror_ref = target.ref if target.mirrored else None
            warnings = [w for w in (img.warnings or []) if not w.startswith(("mirror failed", "all scanners failed",
                                                                                "only one scanner"))]
            warnings += target.warnings
            if not analysis.succeeded and ctx.enabled:
                warnings.append("all scanners failed; score unavailable")
            elif len(analysis.succeeded) == 1 and len(ctx.enabled) > 1:
                warnings.append("only one scanner succeeded (low confidence)")
            img.warnings = warnings
            img.last_scanned_at = ts
            img.last_scan_id = ctx.scan_id
            s.add(ScanSnapshot(scan_id=ctx.scan_id, level="image", key=str(image_id), score=img.score, grade=img.grade,
                               data={"counts": analysis.counts, "fixable": analysis.fixable, "ref": img.ref}))

    async def _persist_snapshot(self, ctx: ScanContext, inv: InventorySnapshot, key_to_id: dict[str, int]) -> None:
        posture = evaluate_inventory(inv)
        async with self.sm() as s:
            imgs = (await s.execute(select(Image).where(Image.id.in_(list(key_to_id.values()) or [0])))).scalars().all()
        by_id = {i.id: i for i in imgs}
        images_by_key = {k: ImageInfo(i, by_id[i].ref, by_id[i].score, by_id[i].counts or {})
                         for k, i in key_to_id.items() if i in by_id}
        workloads, namespaces, cluster = aggregate(inv, images_by_key, posture)
        sid = ctx.scan_id
        async with self.sm() as s, s.begin():
            if inv.containers:
                await s.execute(ContainerRow.__table__.insert(), [{
                    "scan_id": sid, "namespace": c.namespace, "pod": c.pod, "container": c.container,
                    "container_type": c.container_type, "image": c.image, "image_id_raw": c.image_id,
                    "image_fk": key_to_id.get(c.image_key or ""), "workload_kind": c.workload_kind,
                    "workload_name": c.workload_name, "pack": c.pack, "running": c.running, "pod_phase": c.pod_phase,
                    "security": c.security} for c in inv.containers])
            results = [r for wp in posture.values() for r in wp.results]
            if results:
                await s.execute(PostureResultRow.__table__.insert(), [{
                    "scan_id": sid, "check_id": r.check_id, "namespace": r.namespace, "kind": r.kind, "name": r.name,
                    "pod": r.pod, "container": r.container, "status": r.status, "severity": r.severity,
                    "detail": r.detail, "weight": r.weight, "system_namespace": r.system_namespace} for r in results])
            if workloads:
                await s.execute(WorkloadRow.__table__.insert(), [{
                    "scan_id": sid, "namespace": w.namespace, "kind": w.kind, "name": w.name, "pack": w.pack,
                    "score": w.score, "grade": w.grade, "vuln_score": w.vuln_score, "posture_score": w.posture_score,
                    "containers": w.containers, "running_containers": w.running_containers, "image_ids": w.image_ids,
                    "posture_passed": w.posture_passed, "posture_failed": w.posture_failed, "counts": w.counts,
                    "system_namespace": w.system_namespace} for w in workloads])
            snaps = [{"scan_id": sid, "level": "workload", "key": f"{w.namespace}/{w.kind}/{w.name}", "score": w.score,
                      "grade": w.grade, "data": {"counts": w.counts, "postureScore": w.posture_score}} for w in workloads]
            snaps += [{"scan_id": sid, "level": "namespace", "key": n.name, "score": n.score, "grade": n.grade,
                       "data": {"pack": n.pack, "managed": n.managed, "workloads": n.workloads, "images": n.images,
                                "counts": n.counts, "posture": n.posture, "containers": n.containers,
                                "runningContainers": n.running_containers}} for n in namespaces]
            running_imgs = [by_id[i] for i in set(key_to_id.values()) if i in by_id and by_id[i].running]
            counts: dict[str, int] = {}
            for im in running_imgs:
                if im.score is None:
                    continue
                for sev, n in (im.counts or {}).items():
                    counts[sev] = counts.get(sev, 0) + int(n)
            snaps.append({"scan_id": sid, "level": "cluster", "key": "", "score": cluster.score, "grade": cluster.grade,
                          "data": {"vulnScore": cluster.vuln_score, "postureScore": cluster.posture_score,
                                   "workloads": cluster.workloads, "namespaces": cluster.namespaces,
                                   "containers": cluster.containers, "runningContainers": cluster.running_containers,
                                   "counts": counts, "inventoryErrors": inv.errors}})
            await s.execute(ScanSnapshot.__table__.insert(), snaps)
            await s.execute(update(Scan).where(Scan.id == sid).values(
                score=cluster.score, grade=cluster.grade, vuln_score=cluster.vuln_score,
                posture_score=cluster.posture_score, inventory_complete=True))
        ctx.add_log(f"cluster score {cluster.score} ({cluster.grade}); {len(workloads)} workloads, "
                    f"{len(namespaces)} namespaces, {len(results)} posture results")
        await self._prune()

    async def _prune(self) -> None:
        async with self.sm() as s, s.begin():
            keep = [r for (r,) in (await s.execute(
                select(Scan.id).where(Scan.inventory_complete.is_(True)).order_by(Scan.id.desc()).limit(KEEP_INVENTORY_SCANS)
            )).all()]
            if keep:
                for model in (ContainerRow, PostureResultRow, WorkloadRow):
                    await s.execute(delete(model).where(model.scan_id.notin_(keep)))
            old = now() - timedelta(days=14)
            await s.execute(update(ImageScan).where(ImageScan.started_at < old, ImageScan.raw_gz.isnot(None))
                            .values(raw_gz=None))

    # ------------------------------------------------------------ main loop
    async def heartbeat(self) -> None:
        self.last_loop_beat = time.monotonic()
        async with self.sm() as s, s.begin():
            row = await s.get(WorkerHeartbeat, 1)
            if row is None:
                row = WorkerHeartbeat(id=1, hostname=self.hostname, started_at=now())
                s.add(row)
            row.beat_at = now()
            row.hostname = self.hostname

    async def poll_once(self) -> bool:
        scan_id = await self.claim_next()
        if scan_id is None:
            return False
        await self.run_scan(scan_id)
        return True

    async def _sync_schedule(self) -> None:
        if self.scheduler is None:
            return
        try:
            async with self.sm() as s:
                st = await app_settings.load(s, self.s)
        except Exception:  # noqa: BLE001
            return
        if st.scan_interval_hours != self._interval_hours:
            self._interval_hours = st.scan_interval_hours
            self.scheduler.add_job(self.enqueue, "interval", hours=st.scan_interval_hours, id="scheduled-scan",
                                   replace_existing=True, max_instances=1, coalesce=True)
            log.info("scheduler.interval", hours=st.scan_interval_hours)

    def start_scheduler(self) -> None:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        self.scheduler = AsyncIOScheduler(timezone="UTC")
        self.scheduler.add_job(self.update_grype_db, "interval", hours=self.s.grype_db_update_hours, id="grype-db",
                               next_run_time=now() + timedelta(seconds=5), max_instances=1, coalesce=True)
        self.scheduler.add_job(self.refresh_scanner_status, "interval", minutes=15, id="scanner-status",
                               next_run_time=now() + timedelta(seconds=30), max_instances=1, coalesce=True)
        self.scheduler.start()

    async def wait_for_db(self) -> None:
        delay = 2.0
        while not self._stop.is_set():
            try:
                async with self.sm() as s:
                    await s.execute(select(func.count()).select_from(Scan))
                return
            except Exception as e:  # noqa: BLE001
                log.warning("worker.db_unavailable", error=str(e)[:200])
                await asyncio.sleep(delay)
                delay = min(delay * 1.5, 30)

    async def run_forever(self) -> None:
        await self.wait_for_db()
        await self.recover_stale()
        self.start_scheduler()
        await self._sync_schedule()
        if self.s.scan_on_start:
            async with self.sm() as s:
                done = await s.scalar(select(func.count()).select_from(Scan).where(Scan.status == "done"))
            if not done:
                await asyncio.sleep(20)  # let the grype DB download first
                await self.enqueue("scheduled", "worker-startup")
        log.info("worker.ready", hostname=self.hostname)
        while not self._stop.is_set():
            try:
                await self.heartbeat()
                await self._sync_schedule()
                ran = await self.poll_once()
            except Exception:  # noqa: BLE001
                log.exception("worker.loop_error")
                ran = False
            if not ran:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.s.worker_poll_seconds)
                except (TimeoutError, asyncio.TimeoutError):
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self.scheduler is not None:
            self.scheduler.shutdown(wait=False)


# ---------------------------------------------------------------- health server
def health_app(worker: Worker):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz():
        age = round(time.monotonic() - worker.last_loop_beat, 1)
        # a long scan keeps the loop inside run_scan; progress flushes still beat
        ok = age < max(600.0, worker.s.scan_timeout_seconds * 3)
        return JSONResponse({"status": "ok" if ok else "stale", "lastHeartbeatAgeSeconds": age},
                            status_code=200 if ok else 503)

    return app


async def _main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    os.makedirs(settings.cache_dir, exist_ok=True)
    from .db.session import get_sessionmaker

    worker = Worker(settings, get_sessionmaker())
    orig_flush = worker._flush_progress

    async def flush_and_beat(ctx: ScanContext) -> None:
        worker.last_loop_beat = time.monotonic()
        await orig_flush(ctx)

    worker._flush_progress = flush_and_beat  # type: ignore[method-assign]

    import uvicorn

    port = int(os.environ.get("WORKER_HEALTH_PORT", "9000"))
    server = uvicorn.Server(uvicorn.Config(health_app(worker), host="0.0.0.0", port=port, log_config=None,
                                           access_log=False, lifespan="off"))
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    loop = asyncio.get_running_loop()
    main_task = asyncio.create_task(worker.run_forever())

    def _shutdown() -> None:
        log.info("worker.stopping")
        worker.stop()
        main_task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _shutdown)
    health = asyncio.create_task(server.serve())
    try:
        await main_task
    except asyncio.CancelledError:
        pass
    finally:
        server.should_exit = True
        await health
        log.info("worker.stopped")


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
