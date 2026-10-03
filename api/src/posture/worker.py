"""Scan worker: `python -m posture.worker` (DESIGN §4).

* Postgres-as-queue: `scans` rows with status `queued`, claimed with
  `SELECT ... FOR UPDATE SKIP LOCKED`.
* Stages (`--stages` / WORKER_STAGES): inventory, scan, provenance, controls, reports.
  One process runs all of them by default. The chart splits them across two
  Deployments with different ServiceAccounts (worker.splitPrivileged): the scan
  worker (`--stages inventory,scan`, no Secrets access) runs inventory + CVE scans,
  stores the inventory on the scan and marks it `scanned`; the privileged worker
  (`--stages provenance,controls,reports`) claims `scanned` scans (status
  `finalizing`), runs provenance, writes the posture snapshot, marks the scan
  `done`, then runs the controls engine and auto-reports.
* Scheduled scans are due `scan_interval_hours` after the newest `done` full scan
  started (computed from the DB on every loop, so worker restarts never reset it).
  APScheduler only drives grype DB updates and the scanner status refresh.
* Pipeline: inventory -> unique images -> mirror -> 3 scanners concurrently per image
  (N images in parallel) -> correlate -> score -> persist -> posture -> aggregates.
* A scanner failure never fails the scan; only an inventory failure does.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import os
import signal
import socket
import time
from collections import deque
from collections.abc import Awaitable, Callable
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import app_settings, compat_store, metrics, report_jobs
from .aggregate import ImageInfo, aggregate
from .analysis import analyze
from .config import Settings, get_settings
from .db.models import (
    CompatReportRow,
    ConsensusFindingRow,
    ContainerRow,
    FindingRow,
    Image,
    ImageScan,
    PostureResultRow,
    Scan,
    ScannerStatus,
    ScanSnapshot,
    VulnRollupRow,
    WorkerHeartbeat,
    WorkloadRow,
)
from .images import identify_image, parse_image_ref
from .inventory import collect
from .inventory_model import (
    ContainerRecord,
    InventorySnapshot,
    NamespaceInfo,
    NebariAppInfo,
    NetworkPolicyInfo,
)
from .logs import get_logger, setup_logging
from .mirror import Mirror, ScanTarget
from .posture_checks import evaluate_inventory
from .provenance import stage as provenance_stage
from .scanners import ClairScanner, GrypeScanner, Scanner, ScanResult, TrivyScanner
from .scanners.base import pack_raw_text, raw_summary
from .admission import order_for_admission, probe_size
from .rollup import write_vuln_rollup
from .views import ACTIVE_SCAN_STATUSES  # queued, running, scanned, finalizing

log = get_logger("posture.worker")

LOG_LINES_KEPT = 200
KEEP_INVENTORY_SCANS = 10
LAST_SEEN_RESOLUTION = timedelta(hours=1)  # images.last_seen_at is bumped at most hourly (m9)
VULN_ROLLUPS_KEPT = 2  # latest done scans whose vuln_rollup rows are kept

ALL_STAGES = ("inventory", "scan", "provenance", "controls", "reports")
SCAN_STAGES = frozenset({"inventory", "scan"})
FINAL_STAGES = frozenset({"provenance", "controls", "reports"})
# scan status flow: queued -> running -> [scanned -> finalizing ->] done | failed | cancelled
STATUS_SCANNED = "scanned"  # scan stage done, waiting for the privileged worker
STATUS_FINALIZING = "finalizing"  # claimed by the privileged worker
INVENTORY_HANDOFF_LEVEL = "inventory"  # scan_snapshots row carrying the inventory between workers
SCHEDULE_RETRY_HOURS = 1.0  # after a failed/cancelled full scan, wait at most this long before retrying


def parse_stages(value: str | Iterable[str] | None) -> frozenset[str]:
    """`--stages inventory,scan` -> frozenset. Empty / None / "all" selects every stage."""
    if value is None:
        items: list[str] = []
    elif isinstance(value, str):
        items = [v.strip().lower() for v in value.split(",") if v.strip()]
    else:
        items = [str(v).strip().lower() for v in value if str(v).strip()]
    if not items or "all" in items:
        return frozenset(ALL_STAGES)
    unknown = sorted(set(items) - set(ALL_STAGES))
    if unknown:
        raise ValueError(f"unknown worker stage(s): {', '.join(unknown)} (valid: {', '.join(ALL_STAGES)})")
    return frozenset(items)


def next_scheduled_scan(last_done_started: datetime | None, last_attempt: datetime | None, interval_hours: float,
                        current: datetime, first_run: datetime | None = None) -> datetime:
    """When the next scheduled full scan is due (DB-derived, survives restarts; review B2).

    * No full scan ever finished: due at `first_run` (default: now, i.e. immediately).
    * Otherwise `interval_hours` after the newest done full scan *started*.
    * A newer failed/cancelled full scan pushes the next attempt to at least
      min(interval, SCHEDULE_RETRY_HOURS) after that attempt, so a scan that keeps
      failing is retried hourly instead of on every poll.
    """
    if last_done_started is None:
        due = first_run or current
    else:
        due = last_done_started + timedelta(hours=interval_hours)
    if last_attempt is not None and (last_done_started is None or last_attempt > last_done_started):
        due = max(due, last_attempt + timedelta(hours=min(interval_hours, SCHEDULE_RETRY_HOURS)))
    return due


def inventory_to_json(inv: InventorySnapshot) -> dict[str, Any]:
    return {
        "containers": [asdict(c) for c in inv.containers],
        "namespaces": {k: asdict(v) for k, v in inv.namespaces.items()},
        "network_policies": None if inv.network_policies is None else [asdict(n) for n in inv.network_policies],
        "nebari_apps": [asdict(a) for a in inv.nebari_apps],
        "collected_at": inv.collected_at.isoformat() if inv.collected_at else None,
        "errors": list(inv.errors),
    }


def inventory_from_json(data: dict[str, Any]) -> InventorySnapshot:
    nps = data.get("network_policies")
    collected = data.get("collected_at")
    return InventorySnapshot(
        containers=[ContainerRecord(**c) for c in data.get("containers") or []],
        namespaces={k: NamespaceInfo(**v) for k, v in (data.get("namespaces") or {}).items()},
        network_policies=None if nps is None else [NetworkPolicyInfo(**n) for n in nps],
        nebari_apps=[NebariAppInfo(**a) for a in data.get("nebari_apps") or []],
        collected_at=datetime.fromisoformat(collected) if collected else None,
        errors=list(data.get("errors") or []),
    )


def now() -> datetime:
    return datetime.now(UTC)


def pack_raw(r: ScanResult, max_gz: int) -> tuple[bytes | None, int, bool]:
    """gzip raw scanner output for `image_scans.raw_gz`, never cut into invalid JSON: output whose
    gzip exceeds RAW_MAX_GZ_BYTES is replaced by a small `{"truncated": true, ...}` summary."""
    if r.raw_gz is not None:
        if len(r.raw_gz) <= max_gz:
            return r.raw_gz, r.raw_size, r.raw_truncated
        return gzip.compress(raw_summary(r.scanner, r.raw_size, max_gz, len(r.findings))), r.raw_size, True
    if r.raw is None:
        return None, 0, False
    return pack_raw_text(r.raw, r.scanner, max_gz, len(r.findings))


def build_scanners(s: Settings) -> dict[str, Scanner]:
    docker_config = os.environ.get("DOCKER_CONFIG")
    return {
        "trivy": TrivyScanner(s.trivy_server_url, s.trivy_bin, s.cache_dir, docker_config, s.raw_max_gz_bytes),
        "grype": GrypeScanner(s.grype_bin, s.cache_dir, docker_config, s.grype_max_concurrent, s.raw_max_gz_bytes),
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
    supply_chain: dict[int, Any] = field(default_factory=dict)  # image id -> SupplyChainInputs (DESIGN §12)

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
        stages: str | Iterable[str] | None = None,
    ):
        self.s = settings
        self.stages = parse_stages(stages if stages is not None else getattr(settings, "worker_stages", None))
        self.scan_side = bool(self.stages & SCAN_STAGES)
        self.final_side = bool(self.stages & FINAL_STAGES)
        # heartbeat row per role so a split deployment does not clobber one row
        self.heartbeat_id = 1 if self.scan_side else 2
        self.sm = sessionmaker
        self.scanners = scanners if scanners is not None else build_scanners(settings)
        self.inventory_fn = inventory_fn or collect
        self.mirror = mirror if mirror is not None else Mirror(settings)
        self.last_loop_beat = time.monotonic()
        self.hostname = socket.gethostname()
        self._stop = asyncio.Event()
        self.scheduler = None
        self.started = now()
        self._next_due: datetime | None = None
        self._versions: dict[str, str] = {}
        self._metrics_at = 0.0
        self._scanning = 0
        self._grype_lock = asyncio.Lock()
        self._grype_update_pending = False
        self._parallelism = settings.scan_parallelism
        self.report_worker = None
        self.pod_watcher = None
        self._excluded_ns: list[str] = []
        self.provenance_stage: provenance_stage.ProvenanceStage | None = (
            provenance_stage.ProvenanceStage(settings, sessionmaker) if "provenance" in self.stages else None)

    # ------------------------------------------------------------------ queue
    async def enqueue(self, trigger: str = "scheduled", requested_by: str | None = None, force: bool = False) -> int | None:
        async with self.sm() as s, s.begin():
            active = await s.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES),
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

    async def claim_scanned(self) -> int | None:
        """Privileged worker: claim a scan whose scan stage finished (`scanned` -> `finalizing`)."""
        async with self.sm() as s, s.begin():
            scan = (await s.execute(
                select(Scan).where(Scan.status == STATUS_SCANNED).order_by(Scan.id).limit(1)
                .with_for_update(skip_locked=True)
            )).scalar_one_or_none()
            if scan is None:
                return None
            scan.status = STATUS_FINALIZING
            scan.heartbeat_at = now()
            return scan.id

    async def recover_stale(self) -> None:
        """One replica per role: rows this role left mid-flight were orphaned by a restart.

        Scan side: `running` -> failed. Final side: `finalizing` -> `scanned` again (retried),
        or `done` when its posture snapshot was already written (only controls/reports lost)."""
        async with self.sm() as s, s.begin():
            if self.scan_side:
                res = await s.execute(
                    update(Scan).where(Scan.status == "running")
                    .values(status="failed", finished_at=now(), error="worker restarted during scan")
                )
                if res.rowcount:
                    log.warning("scan.recovered_stale", count=res.rowcount)
            if self.final_side:
                for scan in (await s.execute(select(Scan).where(Scan.status == STATUS_FINALIZING))).scalars():
                    snap = await s.scalar(select(func.count()).select_from(ScanSnapshot).where(
                        ScanSnapshot.scan_id == scan.id, ScanSnapshot.level == "cluster"))
                    scan.status = "done" if snap else STATUS_SCANNED
                    if snap:
                        scan.finished_at = scan.finished_at or now()
                    log.warning("scan.recovered_finalizing", scan_id=scan.id, status=scan.status)

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

    async def update_grype_db(self) -> bool:
        """`grype db update` on the shared /cache/grype, never while a scan runs grype against it
        (m7): skipped and retried after the scan; a scan that starts meanwhile waits for it."""
        grype = self.scanners.get("grype")
        if not isinstance(grype, GrypeScanner):
            return False
        if self._scanning:
            self._grype_update_pending = True
            log.info("grype.db_update.deferred", reason="scan running")
            return False
        async with self._grype_lock:
            if self._scanning:  # a scan slipped in while we waited for the lock
                self._grype_update_pending = True
                return False
            self._grype_update_pending = False
            log.info("grype.db_update.start")
            ok, err = await grype.update_db()
        metrics.GRYPE_DB_UPDATES.labels("ok" if ok else "error").inc()
        if ok:
            log.info("grype.db_update.done")
        else:
            log.error("grype.db_update.failed", error=err)
        await self.refresh_scanner_status(["grype"])
        return ok

    @contextlib.asynccontextmanager
    async def scanning(self):
        """Marks the image-scanning phase: waits for a running grype DB update, blocks new ones."""
        async with self._grype_lock:
            self._scanning += 1
        try:
            yield
        finally:
            self._scanning -= 1
            if not self._scanning and self._grype_update_pending:
                self._grype_update_pending = False
                asyncio.create_task(self.update_grype_db())

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
        enabled = self.enabled_scanners(settings)
        ctx = ScanContext(scan_id, settings, enabled)
        ctx.per_scanner = {n: {"ok": 0, "error": 0} for n in enabled}
        ctx.add_log(f"scan started (scanners: {', '.join(enabled) or 'none'})")
        if self.clair_skipped(settings):
            ctx.add_log(f"clair skipped: it needs MIRROR_MODE=registry (mirror mode is {self.mirror_mode})")
            log.warning("scan.clair_skipped", scan_id=scan_id, mirror_mode=self.mirror_mode)
        log.info("scan.started", scan_id=scan_id, scanners=",".join(enabled), force=force)
        progress = asyncio.create_task(self._progress_loop(ctx))
        prov_task: asyncio.Task | None = None
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
            # supply-chain checks run concurrently with CVE scanning (DESIGN §12)
            prov_task = provenance_stage.start(self.provenance_stage, scan_id, settings, inv, key_to_id, ctx.add_log, force)
            to_scan = await self._select_images(key_to_id, inv, target_ids, target_ns, force, settings)
            async with self.sm() as s, s.begin():
                await s.execute(update(Scan).where(Scan.id == scan_id).values(images_total=len(to_scan)))
            ctx.add_log(f"{len(to_scan)} image(s) to scan, {len(key_to_id)} unique image(s) in inventory")
            if enabled and to_scan:  # outside the scanning window: may wait for the first grype DB update
                await self._wait_scanners_ready(ctx, enabled)
            async with self.scanning():  # m7: no grype DB update during the scan
                if enabled:
                    await self.refresh_scanner_status(enabled)
                self._parallelism = max(1, settings.parallelism)
                sem = asyncio.Semaphore(self._parallelism)
                max_bytes = int(max(0.0, self.s.scan_max_image_gb) * 1024**3)
                sizes = await self._image_sizes(to_scan) if max_bytes else {}
                to_scan, deferred = order_for_admission(to_scan, sizes, max_bytes)

                async def one(image_id: int) -> None:
                    try:
                        await self._process_image(ctx, image_id)
                    except Exception as e:  # noqa: BLE001  (never fail the scan for one image)
                        log.exception("image.failed", scan_id=scan_id, image_id=image_id)
                        ctx.failed += 1
                        ctx.done += 1
                        ctx.add_log(f"image {image_id}: internal error {e}")

                async def guarded(image_id: int) -> None:
                    async with sem:
                        if ctx.cancelled:
                            return
                        if max_bytes and sizes.get(image_id) is None and not await self._admit(ctx, image_id, max_bytes):
                            deferred.append(image_id)
                            return
                        await one(image_id)

                await asyncio.gather(*(guarded(i) for i in to_scan))
                if deferred and not ctx.cancelled:  # admission (M2): big images last, one at a time
                    ctx.add_log(f"warning: {len(deferred)} image(s) larger than {self.s.scan_max_image_gb:g} GB "
                                "(SCAN_MAX_IMAGE_GB) scanned last, one at a time")
                    metrics.IMAGES_DEFERRED.inc(len(deferred))
                    for image_id in deferred:
                        if ctx.cancelled:
                            break
                        await one(image_id)
            await self._flush_progress(ctx)
            if ctx.cancelled:
                await provenance_stage.finish(prov_task, ctx.add_log, cancel=True)
                ctx.add_log("scan cancelled")
                await self._finish(ctx, "cancelled")
                return
            if not self.final_side:
                await self._handoff(ctx, inv)
                return
            ctx.supply_chain = await provenance_stage.finish(prov_task, ctx.add_log)
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
            if prov_task is not None and not prov_task.done():
                prov_task.cancel()
        if completed:
            await self._after_done(scan_id, settings)

    async def _after_done(self, scan_id: int, settings: app_settings.AppSettings) -> None:
        try:  # §1: render the provenance-collector-pack report once; the compat API serves the bytes
            async with self.sm() as s, s.begin():
                await compat_store.materialize(s, scan_id, settings.system_name,
                                               getattr(self.provenance_stage, "collector_version", None))
        except Exception:  # noqa: BLE001  (the compat API falls back to rendering on request)
            log.exception("compat.materialize_failed", scan_id=scan_id)
        async with self.sm() as s:
            trigger = await s.scalar(select(Scan.trigger).where(Scan.id == scan_id))
        # event scans (pod watcher) are small and frequent: no auto-generated reports for them
        if "reports" in self.stages and settings.reports.auto_generate and trigger != "event":
            await self.auto_generate_reports(scan_id, settings.reports.auto_generate)
        if "controls" in self.stages:  # DESIGN §13: control evidence stage after every completed scan
            await self.run_controls(trigger="scan", scan_id=scan_id)

    async def _handoff(self, ctx: ScanContext, inv: InventorySnapshot) -> None:
        """Scan worker (no provenance/controls stages): park the inventory on the scan for the
        privileged worker and mark the scan `scanned`."""
        async with self.sm() as s, s.begin():
            await s.execute(delete(ScanSnapshot).where(ScanSnapshot.scan_id == ctx.scan_id,
                                                       ScanSnapshot.level == INVENTORY_HANDOFF_LEVEL))
            s.add(ScanSnapshot(scan_id=ctx.scan_id, level=INVENTORY_HANDOFF_LEVEL, key="",
                               data=inventory_to_json(inv)))
        ctx.add_log("scan stage done; waiting for the privileged worker (provenance, posture, controls, reports)")
        await self._finish(ctx, STATUS_SCANNED)

    async def finalize_scan(self, scan_id: int) -> None:
        """Privileged worker: provenance + posture snapshot for a `finalizing` scan, then `done`."""
        async with self.sm() as s:
            scan = await s.get(Scan, scan_id)
            settings = await app_settings.load(s, self.s)
            row = (await s.execute(select(ScanSnapshot).where(
                ScanSnapshot.scan_id == scan_id, ScanSnapshot.level == INVENTORY_HANDOFF_LEVEL).limit(1)
            )).scalar_one_or_none()
            force = scan.force
            ctx = ScanContext(scan_id, settings, [])
            ctx.log_lines.extend(scan.log or [])
            ctx.done, ctx.failed = scan.images_done, scan.images_failed
            ctx.per_scanner = {k: dict(v) for k, v in (scan.per_scanner or {}).items()}
            inv_data = row.data if row is not None else None
        if inv_data is None:
            await self._finish(ctx, "failed", error="inventory hand-off missing (scan stage did not store it)")
            return
        inv = inventory_from_json(inv_data)
        keys = sorted({c.image_key for c in inv.containers if c.image_key})
        async with self.sm() as s:
            key_to_id = {k: i for k, i in (await s.execute(select(Image.key, Image.id).where(
                Image.key.in_(keys or [""])))).all()}
        ctx.add_log(f"finalize: {', '.join(sorted(self.stages & FINAL_STAGES))}")
        log.info("scan.finalize", scan_id=scan_id)
        progress = asyncio.create_task(self._progress_loop(ctx))
        completed = False
        try:
            prov_task = provenance_stage.start(self.provenance_stage, scan_id, settings, inv, key_to_id,
                                               ctx.add_log, force)
            ctx.supply_chain = await provenance_stage.finish(prov_task, ctx.add_log)
            await self._flush_progress(ctx)
            if ctx.cancelled:
                await self._finish(ctx, "cancelled")
                return
            await self._persist_snapshot(ctx, inv, key_to_id)
            async with self.sm() as s, s.begin():
                await s.execute(delete(ScanSnapshot).where(ScanSnapshot.scan_id == scan_id,
                                                           ScanSnapshot.level == INVENTORY_HANDOFF_LEVEL))
            await self._finish(ctx, "done")
            completed = True
        except asyncio.CancelledError:
            await self._finish(ctx, "failed", error="worker shutting down")
            raise
        except Exception as e:  # noqa: BLE001
            log.exception("scan.finalize_failed", scan_id=scan_id)
            await self._finish(ctx, "failed", error=str(e)[:2000])
        finally:
            progress.cancel()
        if completed:
            await self._after_done(scan_id, settings)

    async def scanners_not_ready(self, enabled: list[str]) -> list[str]:
        """Reasons why an enabled scanner would fail or return empty results right now."""
        reasons: list[str] = []
        grype = self.scanners.get("grype")
        if "grype" in enabled and isinstance(grype, GrypeScanner):
            st = await grype.db_status()
            if not st.get("valid"):
                reasons.append(f"grype: vulnerability DB not ready ({st.get('error') or 'invalid'})")
        clair = self.scanners.get("clair")
        if "clair" in enabled and isinstance(clair, ClairScanner):
            ok, err = await clair.healthy()
            if not ok:
                reasons.append(f"clair: {err}")
            else:
                ops = await clair.update_operations() or {}
                missing = [u for u in self.s.clair_ready_updaters if not any(u in k for k in ops)]
                if missing:
                    reasons.append(f"clair: initial vulnerability updates not finished (waiting for {', '.join(missing)})")
        return reasons

    async def _wait_scanners_ready(self, ctx: ScanContext, enabled: list[str]) -> None:
        deadline = time.monotonic() + max(0.0, self.s.scanner_ready_timeout_seconds)
        logged: set[str] = set()
        while not ctx.cancelled:
            reasons = await self.scanners_not_ready(enabled)
            if not reasons:
                if logged:
                    ctx.add_log("scanners ready")
                return
            for r in reasons:
                if r not in logged:
                    ctx.add_log(f"waiting: {r}")
                    log.info("scan.waiting_for_scanner", scan_id=ctx.scan_id, reason=r)
                    logged.add(r)
            if time.monotonic() >= deadline:
                ctx.add_log("scanner readiness timeout; scanning anyway: " + "; ".join(reasons))
                log.warning("scan.scanner_not_ready", scan_id=ctx.scan_id, reasons="; ".join(reasons))
                return
            await asyncio.sleep(15)

    async def auto_generate_reports(self, scan_id: int, types: list[str]) -> list[str]:
        """Settings `reports.autoGenerate`: queue one cluster-scope report per type in its default
        format. The report worker generates them (posture.report_worker); the scan loop never
        blocks on report generation. Returns the queued report ids."""
        return await report_jobs.enqueue_auto(self.sm, scan_id, types)

    async def _finish(self, ctx: ScanContext, status: str, error: str | None = None) -> None:
        async with self.sm() as s, s.begin():
            scan = await s.get(Scan, ctx.scan_id, with_for_update=True)
            if scan is None:
                return
            if scan.status == "cancelled" and status != "cancelled":
                status = "cancelled"
            scan.status = status
            if status != STATUS_SCANNED:
                scan.finished_at = now()
            scan.images_done = ctx.done
            scan.images_failed = ctx.failed
            scan.per_scanner = {k: dict(v) for k, v in ctx.per_scanner.items()}
            if error:
                scan.error = error
                ctx.add_log(f"error: {error}")
            ctx.add_log(f"scan {status}" if status != STATUS_SCANNED else "scan stage finished")
            scan.log = list(ctx.log_lines)
            if status in ("done", "failed", "cancelled") and scan.started_at is not None:
                metrics.SCAN_DURATION.labels(scan.trigger, status).observe(
                    max(0.0, (scan.finished_at - scan.started_at).total_seconds()))
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
            # m9: touch only rows that change (was: UPDATE images SET running=false on every row)
            await s.execute(update(Image).where(Image.running.is_(True), Image.key.notin_(list(info) or [""]))
                            .values(running=False).execution_options(synchronize_session=False))

            def put(img: Image, attr: str, value: Any) -> None:
                if getattr(img, attr) != value:
                    setattr(img, attr, value)

            for key, e in info.items():
                ref = e["ident"].ref
                img = existing.get(key)
                if img is None:
                    img = Image(key=key, registry_host=ref.registry, repository=ref.repository, digest=ref.digest,
                                counts={}, fixable={}, scanners={}, warnings=[], tags=[], namespaces=[], first_seen_at=ts)
                    s.add(img)
                put(img, "ref", ref.display)
                put(img, "tag", ref.tag or img.tag)
                put(img, "tags", sorted(set(img.tags or []) | e["tags"]))
                put(img, "namespaces", sorted(e["namespaces"]))
                put(img, "workloads", len(e["workloads"]))
                put(img, "containers", e["containers"])
                put(img, "running", e["running"])
                if img.last_seen_at is None or ts - img.last_seen_at > LAST_SEEN_RESOLUTION:
                    img.last_seen_at = ts
                base = [w for w in (img.warnings or []) if not w.startswith(("imageID", "unparseable"))]
                put(img, "warnings", sorted(set(base) | set(e["ident"].warnings)))
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
        enabled = self.enabled_scanners(settings)
        out = []
        for img in imgs:
            runs = img.scanners or {}
            # a scanner that errored / timed out / never ran on this digest makes it stale
            complete = all((runs.get(n) or {}).get("status") in ("ok", "unsupported") for n in enabled)
            fresh = (img.last_scanned_at is not None and img.last_scanned_at > cutoff and img.score is not None
                     and complete)
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
        # an adapter with a concurrency cap (grype) may wait for a slot before its own timeout
        # starts: the safety net covers the wait for the runs queued ahead of it
        cap = getattr(scanner, "max_concurrent", None)
        rounds = 1 + (-(-max(1, self._parallelism) // cap) if isinstance(cap, int) and cap > 0 else 0)
        try:
            return await asyncio.wait_for(
                scanner.scan(target.ref, insecure=target.insecure, timeout=self.s.scan_timeout_seconds),
                self.s.scan_timeout_seconds * rounds + 30,
            )
        except (TimeoutError, asyncio.TimeoutError):
            return ScanResult(name, "timeout", error=f"timed out after {self.s.scan_timeout_seconds}s")
        except Exception as e:  # noqa: BLE001
            return ScanResult(name, "error", error=f"adapter error: {e}")

    @property
    def mirror_mode(self) -> str:
        return getattr(self.mirror, "mode", "registry")

    def clair_skipped(self, settings: app_settings.AppSettings) -> bool:
        """Clair pulls through clairctl from a registry only: with MIRROR_MODE local or off there
        is no registry copy for it, so it is left out (logged) instead of failing every image."""
        return bool(settings.scanners.clair) and "clair" in self.scanners and self.mirror_mode != "registry"

    def enabled_scanners(self, settings: app_settings.AppSettings) -> list[str]:
        out = [n for n in ("trivy", "grype", "clair") if getattr(settings.scanners, n) and n in self.scanners]
        return [n for n in out if not (n == "clair" and self.clair_skipped(settings))]

    async def _image_sizes(self, ids: list[int]) -> dict[int, int | None]:
        async with self.sm() as s:
            return {i: size for i, size in (await s.execute(
                select(Image.id, Image.size_bytes).where(Image.id.in_(ids or [0])))).all()}

    async def _admit(self, ctx: ScanContext, image_id: int, max_bytes: int) -> bool:
        """Probe an image's size once per digest (kept in images.size_bytes); False = defer it."""
        async with self.sm() as s:
            img = await s.get(Image, image_id)
            if img is None:
                return True
            ref, display = self._image_ref(img), img.ref
        size = await probe_size(self.mirror, ref)
        if size is None:
            return True
        async with self.sm() as s, s.begin():
            await s.execute(update(Image).where(Image.id == image_id).values(size_bytes=size))
        if size > max_bytes:
            ctx.add_log(f"{display}: {size / 1024**3:.1f} GB exceeds SCAN_MAX_IMAGE_GB; moved to the end of the queue")
            log.warning("scan.image_deferred", scan_id=ctx.scan_id, image_id=image_id, size=size)
            return False
        return True

    @staticmethod
    def _image_ref(img: Image):
        ref = parse_image_ref(img.key)
        if img.tag and not ref.tag:
            ref = type(ref)(ref.registry, ref.repository, img.tag, ref.digest)
        return ref

    async def _process_image(self, ctx: ScanContext, image_id: int) -> None:
        async with self.sm() as s:
            img = await s.get(Image, image_id)
            if img is None:
                ctx.done += 1
                return
            ref = self._image_ref(img)
            display = img.ref
        started = now()
        target = await self.mirror.prepare(ref)
        for w in target.warnings:
            ctx.add_log(f"{display}: {w}")
        try:
            results = await asyncio.gather(*(self._scan_one(n, target) for n in ctx.enabled)) if ctx.enabled else []
        finally:
            release = getattr(self.mirror, "release", None)
            if callable(release):
                release(target)
        analysis = analyze(list(results))
        for r in results:
            metrics.observe_scanner(r.scanner, r.status, r.duration_ms)
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
                raw_gz, raw_size, truncated = pack_raw(r, self.s.raw_max_gz_bytes)
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
                # SLA clock (compliance review M5): first seen per (repository, vulnId, package) across
                # every digest of the repository, so a rebuild / retag that still carries the CVE keeps
                # the original first-seen date instead of restarting the remediation clock.
                prev = {(v, p): t for v, p, t in (await s.execute(
                    select(ConsensusFindingRow.vuln_id, ConsensusFindingRow.package,
                           func.min(ConsensusFindingRow.first_seen_at))
                    .join(Image, Image.id == ConsensusFindingRow.image_id)
                    .where(Image.registry_host == img.registry_host, Image.repository == img.repository)
                    .group_by(ConsensusFindingRow.vuln_id, ConsensusFindingRow.package))).all()}
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
            mref = target.ref
            if target.mirrored and getattr(target, "digest_verified", False) and "@" not in mref \
                    and getattr(target, "mirror_digest", None):
                mref = f"{mref}@{target.mirror_digest}"  # local OCI layout: show the verified digest
            img.mirror_ref = mref if target.mirrored else None
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
        workloads, namespaces, cluster = aggregate(inv, images_by_key, posture, ctx.supply_chain)
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
            fixable: dict[str, int] = {}
            for im in running_imgs:
                if im.score is None:
                    continue
                for sev, n in (im.counts or {}).items():
                    counts[sev] = counts.get(sev, 0) + int(n)
                for sev, n in (im.fixable or {}).items():
                    fixable[sev] = fixable.get(sev, 0) + int(n)
            # /summary reads these instead of recomputing over every image (architecture M4)
            top = sorted((i for i in running_imgs if i.score is not None), key=lambda i: (i.score, -i.id))[:10]
            top_risks = [{"imageId": i.id, "ref": i.ref, "score": i.score, "grade": i.grade,
                          "critical": int((i.counts or {}).get("critical", 0) or 0),
                          "high": int((i.counts or {}).get("high", 0) or 0), "workloads": i.workloads} for i in top]
            snaps.append({"scan_id": sid, "level": "cluster", "key": "", "score": cluster.score, "grade": cluster.grade,
                          "data": {"vulnScore": cluster.vuln_score, "postureScore": cluster.posture_score,
                                   "supplyChainScore": cluster.supply_chain_score,
                                   "workloads": cluster.workloads, "namespaces": cluster.namespaces,
                                   "containers": cluster.containers, "runningContainers": cluster.running_containers,
                                   "counts": counts, "fixable": fixable, "topRisks": top_risks,
                                   "inventoryErrors": inv.errors}})
            await s.execute(ScanSnapshot.__table__.insert(), snaps)
            rolled = await write_vuln_rollup(s, sid)
            await s.execute(update(Scan).where(Scan.id == sid).values(
                score=cluster.score, grade=cluster.grade, vuln_score=cluster.vuln_score,
                posture_score=cluster.posture_score, inventory_complete=True))
        ctx.add_log(f"cluster score {cluster.score} ({cluster.grade}); {len(workloads)} workloads, "
                    f"{len(namespaces)} namespaces, {len(results)} posture results, {rolled} vulnerabilities")
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
        await self.prune_history()

    async def prune_history(self, retain: int | None = None) -> dict[str, int]:
        """HISTORY_RETAIN_SCANS (30): drop image_scans (and their raw JSON), scan_snapshots and
        compat reports of finished scans older than the newest N. The newest done scan is always
        kept, and so is every image_scans row the current findings still reference."""
        retain = self.s.history_retain_scans if retain is None else retain
        out = {"image_scans": 0, "scan_snapshots": 0, "vuln_rollup": 0, "compat_reports": 0}
        if retain <= 0:
            return out
        async with self.sm() as s, s.begin():
            keep = {r for (r,) in (await s.execute(select(Scan.id).order_by(Scan.id.desc()).limit(retain))).all()}
            latest_done = await s.scalar(select(func.max(Scan.id)).where(Scan.status == "done"))
            if latest_done is not None:
                keep.add(latest_done)
            if not keep:
                return out
            floor = min(keep)
            finished = select(Scan.id).where(Scan.id < floor, Scan.status.in_(("done", "failed", "cancelled")),
                                             Scan.id.notin_(keep))
            referenced = select(FindingRow.id).where(FindingRow.image_scan_id == ImageScan.id).exists()
            out["image_scans"] = (await s.execute(delete(ImageScan).where(
                ImageScan.scan_id.in_(finished), ~referenced))).rowcount or 0
            out["scan_snapshots"] = (await s.execute(delete(ScanSnapshot).where(
                ScanSnapshot.scan_id.in_(finished)))).rowcount or 0
            out["compat_reports"] = (await s.execute(delete(CompatReportRow).where(
                CompatReportRow.scan_id.in_(finished)))).rowcount or 0
            rollups = [r for (r,) in (await s.execute(select(Scan.id).where(
                Scan.status == "done", Scan.vuln_rollup_at.isnot(None)).order_by(Scan.id.desc())
                .limit(VULN_ROLLUPS_KEPT))).all()]
            if rollups:
                out["vuln_rollup"] = (await s.execute(delete(VulnRollupRow).where(
                    VulnRollupRow.scan_id < min(rollups)))).rowcount or 0
        if any(out.values()):
            log.info("history.pruned", retain=retain, **out)
        return out

    # ------------------------------------------------------------ controls (DESIGN §13)
    async def run_controls(self, trigger: str = "scan", scan_id: int | None = None,
                           run_id: int | None = None) -> int | None:
        """Run the control evidence engine once (best effort; never fails the worker)."""
        if not self.s.controls_engine_enabled:
            return None
        from .controls_engine import engine as controls_engine

        try:
            return await controls_engine.execute(self.sm, self.s, run_id=run_id, trigger=trigger, scan_id=scan_id,
                                                 context_factory=getattr(self, "controls_context_factory", None))
        except Exception:  # noqa: BLE001
            log.exception("controls.failed", trigger=trigger)
            return None

    async def poll_controls(self) -> bool:
        """On-demand runs: `control_assertion_runs` rows queued by POST /compliance/assertions/run."""
        if "controls" not in self.stages or not self.s.controls_engine_enabled:
            return False
        from .controls_engine import engine as controls_engine

        run_id = await controls_engine.claim_queued(self.sm)
        if run_id is None:
            return False
        await self.run_controls(trigger="manual", run_id=run_id)
        return True

    async def recover_controls(self) -> None:
        from .controls_engine import engine as controls_engine

        try:
            await controls_engine.fail_stale(self.sm, timedelta(0))
        except Exception:  # noqa: BLE001  (tables missing before migration)
            log.warning("controls.recover_failed")

    # ------------------------------------------------------------ main loop
    async def heartbeat(self) -> None:
        self.last_loop_beat = time.monotonic()
        async with self.sm() as s, s.begin():
            row = await s.get(WorkerHeartbeat, self.heartbeat_id)
            if row is None:
                row = WorkerHeartbeat(id=self.heartbeat_id, hostname=self.hostname, started_at=now())
                s.add(row)
            row.beat_at = now()
            row.hostname = self.hostname

    async def poll_once(self) -> bool:
        if self.scan_side:
            scan_id = await self.claim_next()
            if scan_id is not None:
                await self.run_scan(scan_id)
                return True
        if self.final_side:
            scan_id = await self.claim_scanned()
            if scan_id is not None:
                await self.finalize_scan(scan_id)
                return True
        return await self.poll_controls()

    async def next_scan_due(self) -> datetime | None:
        """Next scheduled full scan from the DB (None when this worker does not run scans)."""
        if not self.scan_side:
            return None
        async with self.sm() as s:
            st = await app_settings.load(s, self.s)
            # targeted scans (image ids, namespaces: e.g. pod-watcher event scans) do not reset the schedule
            full = Scan.target_image_ids.is_(None) & Scan.target_namespaces.is_(None)
            self._excluded_ns = list(st.excluded_namespaces)
            last_done = await s.scalar(select(func.max(Scan.started_at)).where(Scan.status == "done", full))
            last_attempt = await s.scalar(select(func.max(Scan.created_at)).where(
                Scan.status.in_(("failed", "cancelled")), full))
        first = now() if self.s.scan_on_start else self.started + timedelta(hours=st.scan_interval_hours)
        return next_scheduled_scan(last_done, last_attempt, st.scan_interval_hours, now(), first)

    async def maybe_enqueue_scheduled(self) -> int | None:
        due = await self.next_scan_due()
        if due is None:
            return None
        if due != self._next_due:
            self._next_due = due
            log.info("scheduler.next_scan", due=due.isoformat())
        if now() < due:
            return None
        return await self.enqueue("scheduled")

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

    def start_report_worker(self) -> asyncio.Task | None:
        """REPORT_WORKER_EMBEDDED: drain the reports queue from this process too (one report at a
        time, each in a child process) until the chart runs a report-worker Deployment."""
        if "reports" not in self.stages or not self.s.report_worker_embedded:
            return None
        from .report_worker import ReportWorker

        self.report_worker = ReportWorker(self.s, self.sm)
        return asyncio.create_task(self.report_worker.run_forever(refresh_metrics=False))

    def start_pod_watcher(self) -> asyncio.Task | None:
        """EVENT_SCANS_ENABLED (m11): targeted scans for new digests within a minute."""
        if not self.scan_side or not self.s.event_scans_enabled:
            return None
        from .event_scans import PodWatcher

        self.pod_watcher = PodWatcher(self.sm, lambda: self._excluded_ns or self.s.excluded_namespaces,
                                      debounce=self.s.event_scan_debounce_seconds)
        return asyncio.create_task(self.pod_watcher.run())

    async def _refresh_metrics(self) -> None:
        if time.monotonic() - self._metrics_at < 30:
            return
        self._metrics_at = time.monotonic()
        async with self.sm() as s:
            await metrics.refresh_db_gauges(s)

    async def run_forever(self) -> None:
        await self.wait_for_db()
        await self.recover_stale()
        if "controls" in self.stages:
            await self.recover_controls()
        if self.scan_side:
            self.start_scheduler()
        # first scan immediately when none ever finished (run_scan waits for the grype DB /
        # Clair updaters itself); afterwards interval after the newest done scan (B2)
        try:
            await self.maybe_enqueue_scheduled()
        except Exception:  # noqa: BLE001  (schema still migrating)
            log.exception("scheduler.startup_check_failed")
        log.info("worker.ready", hostname=self.hostname, stages=",".join(s for s in ALL_STAGES if s in self.stages))
        reports_task = self.start_report_worker()
        watch_task = self.start_pod_watcher()
        try:
            await self._loop()
        finally:
            if reports_task is not None:
                self.report_worker.stop()
                reports_task.cancel()
            if watch_task is not None:
                self.pod_watcher.stop()
                watch_task.cancel()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._refresh_metrics()
                await self.heartbeat()
                await self.maybe_enqueue_scheduled()
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

    @app.get("/metrics")
    async def prom():
        from fastapi.responses import Response

        body, ctype = metrics.exposition()
        return Response(body, media_type=ctype)

    @app.get("/healthz")
    async def healthz():
        age = round(time.monotonic() - worker.last_loop_beat, 1)
        # a long scan keeps the loop inside run_scan; progress flushes still beat
        ok = age < max(600.0, worker.s.scan_timeout_seconds * 3)
        return JSONResponse({"status": "ok" if ok else "stale", "lastHeartbeatAgeSeconds": age},
                            status_code=200 if ok else 503)

    return app


async def _main(stages: str | None = None) -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    os.makedirs(settings.cache_dir, exist_ok=True)
    from .db.session import get_sessionmaker

    worker = Worker(settings, get_sessionmaker(), stages=stages)
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


def main(argv: list[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m posture.worker")
    parser.add_argument("--stages", default=None,
                        help=f"comma list of {','.join(ALL_STAGES)} (default: WORKER_STAGES or all)")
    args = parser.parse_args(argv)
    stages = args.stages if args.stages is not None else get_settings().worker_stages
    parse_stages(stages)  # fail fast on a typo
    asyncio.run(_main(stages))


if __name__ == "__main__":
    main()
