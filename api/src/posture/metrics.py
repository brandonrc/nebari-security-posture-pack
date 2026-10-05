"""Prometheus metrics (architecture review M9, docs/OPERATIONS.md).

Two kinds:

* **process metrics** (counters / histograms) recorded where the work happens: scan and
  scanner runs in the scan worker, report generation in the report worker. They reset on a
  restart; use `rate()` / `increase()`.
* **state gauges** read from Postgres by `refresh_db_gauges` (last successful scan, queue
  depths, scanner DB age, latest scan's per-scanner results, report and assertion status).
  Every process that serves `/metrics` refreshes them, so alerts work no matter which pod
  Prometheus scrapes and survive restarts. The api refreshes them on each scrape (throttled),
  the workers in their poll loop.

Served on `/metrics`: api `:8000` (outside `/api/v1`, no auth: keep it off the gateway and
behind the NetworkPolicy), scan worker and report worker `:9000`.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .logs import get_logger

log = get_logger(__name__)

_DURATION_BUCKETS = (30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 14400, 21600, 43200)
_SHORT_BUCKETS = (0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1200)

# ---------------------------------------------------------------- process metrics
SCAN_DURATION = Histogram("posture_scan_duration_seconds", "Wall time of a scan, by trigger and final status.",
                          ["trigger", "status"], buckets=_DURATION_BUCKETS)
SCANNER_RUNS = Counter("posture_scanner_runs_total", "Scanner invocations per image, by scanner and result status.",
                       ["scanner", "status"])
SCANNER_DURATION = Histogram("posture_scanner_duration_seconds", "Scanner run time per image.", ["scanner"],
                             buckets=_SHORT_BUCKETS)
IMAGES_DEFERRED = Counter("posture_scan_images_deferred_total",
                          "Images moved to the end of the scan queue because they exceed SCAN_MAX_IMAGE_GB.")
GRYPE_DB_UPDATES = Counter("posture_grype_db_updates_total", "grype DB update attempts.", ["status"])
EVENT_SCANS = Counter("posture_event_scans_total", "Targeted scans queued by the pod watcher (new digests).")
SCAN_IMAGE_SELECTION = Counter(
    "posture_scan_image_selection_total",
    "Per scan, candidate images by outcome: rescanned (stale/forced/targeted) or skipped_fresh (rescanAfterHours).",
    ["trigger", "result"])
PROVENANCE_IMAGES = Counter(
    "posture_provenance_images_total",
    "Images handled by the provenance stage: checked (registry) or carried (previous result reused, no registry call).",
    ["result"])
POST_SCAN_STAGES = Counter(
    "posture_post_scan_stage_total",
    "Post-scan stages after a done scan, by stage (controls, reports) and action (run, skipped).",
    ["stage", "action"])
IMAGE_CACHE_BYTES = Gauge("posture_image_cache_bytes", "Bytes in the local OCI image cache (MIRROR_MODE=local).")
REPORT_DURATION = Histogram("posture_report_duration_seconds", "Report generation time, by type and status.",
                            ["type", "status"], buckets=_SHORT_BUCKETS)
REPORTS_GENERATED = Counter("posture_reports_generated_total", "Reports finished by the report worker.",
                            ["type", "status"])

# ---------------------------------------------------------------- state gauges (from the DB)
LAST_SUCCESS = Gauge("posture_last_successful_scan_timestamp_seconds",
                     "Finish time of the latest full (untargeted) scan with status done (0 = never).")
SCAN_INTERVAL = Gauge("posture_scan_interval_seconds", "Configured scheduled-scan interval (settings).")
SCAN_IMAGES = Gauge("posture_scan_images",
                    "Images of the latest done full scan, by status (total, done, failed, inventoried, rescanned, "
                    "skipped_fresh).", ["status"])
SCAN_SCANNER_RESULTS = Gauge("posture_scan_scanner_results",
                             "Per-image scanner results of the latest done full scan, by scanner and result (ok, error).",
                             ["scanner", "result"])
SCANNER_DB_AGE = Gauge("posture_scanner_db_age_seconds", "Age of each scanner's vulnerability database.", ["scanner"])
SCANNER_HEALTHY = Gauge("posture_scanner_healthy", "1 when the worker last saw the scanner healthy.", ["scanner"])
QUEUE_DEPTH = Gauge("posture_queue_depth", "Queued rows waiting for a worker, by kind (scans, reports, controls).",
                    ["kind"])
QUEUE_RUNNING = Gauge("posture_queue_running", "Rows currently being processed, by kind.", ["kind"])
QUEUE_OLDEST = Gauge("posture_queue_oldest_age_seconds", "Age of the oldest queued or running row, by kind.",
                     ["kind"])
REPORTS = Gauge("posture_reports", "Rows in the reports table, by status.", ["status"])
REPORTS_FAILED_24H = Gauge("posture_reports_failed_last_24h", "Reports that failed in the last 24 hours.")
ASSERTIONS = Gauge("posture_assertions", "Results of the latest control evidence run, by status.", ["status"])

_last_refresh = 0.0


def exposition() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


def observe_scanner(scanner: str, status: str, duration_ms: int | None) -> None:
    SCANNER_RUNS.labels(scanner, status).inc()
    if duration_ms:
        SCANNER_DURATION.labels(scanner).observe(duration_ms / 1000)


def _age(dt: datetime | None, now: datetime) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return max(0.0, (now - dt).total_seconds())


async def refresh_db_gauges(session: AsyncSession, min_interval: float = 0.0) -> bool:
    """Set the state gauges from the database. Best effort: a missing table (old schema)
    or a DB error leaves the previous values. Returns False when skipped or failed."""
    global _last_refresh
    if min_interval and time.monotonic() - _last_refresh < min_interval:
        return False
    _last_refresh = time.monotonic()
    try:
        await _refresh(session)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("metrics.refresh_failed", error=str(e).splitlines()[0][:200] if str(e) else type(e).__name__)
        try:
            await session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return False


async def _refresh(session: AsyncSession) -> None:
    from . import app_settings
    from .db.models import Report, Scan, ScannerStatus

    now = datetime.now(UTC)
    # Full scans only: targeted scans (pod-watcher event scans, image rescans) cover a few
    # images, so they would report a handful of images and keep PostureScanStale quiet while
    # the scheduled full scans fail. Same definition as the scheduler's next_scan_due().
    full = Scan.target_image_ids.is_(None) & Scan.target_namespaces.is_(None)
    latest = (await session.execute(
        select(Scan).where(Scan.status == "done", full).order_by(Scan.id.desc()).limit(1))).scalar_one_or_none()
    LAST_SUCCESS.set(latest.finished_at.timestamp() if latest and latest.finished_at else 0)
    if latest is not None:
        SCAN_IMAGES.labels("total").set(latest.images_total)
        SCAN_IMAGES.labels("done").set(latest.images_done)
        SCAN_IMAGES.labels("failed").set(latest.images_failed)
        for status in ("inventoried", "rescanned", "skipped_fresh"):
            value = getattr(latest, f"images_{status}", None)
            if value is not None:
                SCAN_IMAGES.labels(status).set(value)
        for scanner, r in (latest.per_scanner or {}).items():
            for result in ("ok", "error"):
                SCAN_SCANNER_RESULTS.labels(scanner, result).set(int((r or {}).get(result, 0) or 0))
    try:
        st = await app_settings.load(session)
        SCAN_INTERVAL.set(float(st.scan_interval_hours) * 3600)
    except Exception:  # noqa: BLE001
        pass

    for row in (await session.execute(select(ScannerStatus))).scalars():
        age = _age(row.db_updated_at, now)
        if age is not None:
            SCANNER_DB_AGE.labels(row.name).set(age)
        SCANNER_HEALTHY.labels(row.name).set(1 if row.healthy else 0)

    queues: dict[str, Any] = {"scans": (Scan, Scan.created_at), "reports": (Report, Report.created_at)}
    try:
        from .controls_engine.models import ControlAssertionRun

        queues["controls"] = (ControlAssertionRun, ControlAssertionRun.created_at)
    except Exception:  # noqa: BLE001
        ControlAssertionRun = None  # type: ignore[assignment]  # noqa: N806
    for kind, (model, created) in queues.items():
        counts = dict((await session.execute(
            select(model.status, func.count()).where(model.status.in_(("queued", "running")))
            .group_by(model.status))).all())
        QUEUE_DEPTH.labels(kind).set(counts.get("queued", 0))
        QUEUE_RUNNING.labels(kind).set(counts.get("running", 0))
        oldest = await session.scalar(select(func.min(created)).where(model.status.in_(("queued", "running"))))
        QUEUE_OLDEST.labels(kind).set(_age(oldest, now) or 0)

    by_status = dict((await session.execute(select(Report.status, func.count()).group_by(Report.status))).all())
    for status in ("queued", "running", "done", "failed"):
        REPORTS.labels(status).set(by_status.get(status, 0))
    REPORTS_FAILED_24H.set(await session.scalar(
        select(func.count()).select_from(Report).where(
            Report.status == "failed", func.coalesce(Report.finished_at, Report.created_at) > now - timedelta(hours=24)
        )) or 0)

    if ControlAssertionRun is not None:
        from .controls_engine.models import ControlAssertionResult

        run_id = await session.scalar(select(ControlAssertionRun.id).where(ControlAssertionRun.status == "done")
                                      .order_by(ControlAssertionRun.id.desc()).limit(1))
        seen: set[str] = set()
        if run_id is not None:
            for status, n in (await session.execute(
                select(ControlAssertionResult.status, func.count()).where(ControlAssertionResult.run_id == run_id)
                .group_by(ControlAssertionResult.status))).all():
                ASSERTIONS.labels(status).set(n)
                seen.add(status)
        for status in ("pass", "fail", "unknown", "not-applicable"):
            if status not in seen:
                ASSERTIONS.labels(status).set(0)
    await session.rollback()  # read-only; release the snapshot
