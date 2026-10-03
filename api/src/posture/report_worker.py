"""Report worker: `python -m posture.report_worker` (architecture review M3, docs/OPERATIONS.md).

The API (`POST /reports`) and the scan worker (settings `reports.autoGenerate`) only insert
`queued` rows. This process drains them, one report at a time:

* **claim**: `UPDATE ... WHERE id = (SELECT ... WHERE status='queued' ORDER BY created_at
  FOR UPDATE SKIP LOCKED LIMIT 1)` sets `running`, `worker_id`, `attempts+1` and a lease
  (`leased_until = now() + REPORT_LEASE_SECONDS`). Any number of report workers can run.
* **heartbeat**: while a report generates, the lease is extended every lease/3 seconds.
* **expired leases** (the worker died: OOM, node drain) are requeued by any report worker;
  after `REPORT_MAX_ATTEMPTS` claims the row is failed instead, so a report that kills its
  worker cannot crash-loop it.
* **isolation** (`REPORT_WORKER_ISOLATION`): `process` (default) generates each report in a
  child process (`python -m posture.report_worker --generate <id>`): the timeout
  (`REPORT_TIMEOUT_SECONDS`, 20 min) can kill it, an OOM kill marks just that report failed,
  and the memory goes back to the OS after every report. `inline` generates in this process
  (tests; small installs).
* **retention** after every report: `REPORTS_RETENTION_PER_TYPE` (20) finished reports per
  type and `REPORTS_MAX_TOTAL_BYTES` (2 GiB) across all of them, oldest first.

`REPORT_WORKER_EMBEDDED=true` (default) also runs this loop inside the scan worker, for charts
that do not deploy the report-worker yet. With a report-worker Deployment, set it to false.
`/healthz` and `/metrics` are served on `WORKER_HEALTH_PORT` (9000).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import signal
import socket
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import metrics, report_jobs
from .config import Settings, get_settings
from .db.models import Report
from .logs import get_logger, setup_logging

log = get_logger("posture.report_worker")


def now() -> datetime:
    return datetime.now(UTC)


_CHILD_EXTRA = ("PYTHONPATH", "PYTHONHOME", "FONTCONFIG_PATH", "FONTCONFIG_FILE", "XDG_CACHE_HOME",
                "XDG_DATA_DIRS")
_CHILD_DENY = re.compile(r"^(OIDC_|CONTROLS_KEYCLOAK_|PROVENANCE_COMPAT_TOKEN)|PASSWORD|SECRET|PRIVATE_KEY",
                         re.IGNORECASE)


def child_env() -> dict[str, str]:
    """Environment of the per-report child: the scanner subprocess allowlist
    (scanners.base.subprocess_env) plus the settings a generator reads (DATABASE_URL,
    REPORTS_DIR, LOG_LEVEL, ...) and Python / fontconfig paths. Credentials the child does not
    need (OIDC, Keycloak, compat token, *PASSWORD*/*SECRET*) never reach it."""
    from .scanners.base import subprocess_env

    fields = {k.upper() for k in Settings.model_fields}
    extra = {k: v for k, v in os.environ.items()
             if (k.upper() in fields or k in _CHILD_EXTRA) and not _CHILD_DENY.search(k)}
    return subprocess_env(extra)


class ReportWorker:
    def __init__(self, settings: Settings, sessionmaker: async_sessionmaker[AsyncSession],
                 worker_id: str | None = None, isolation: str | None = None):
        self.s = settings
        self.sm = sessionmaker
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.isolation = (isolation or settings.report_worker_isolation or "process").lower()
        self.lease = max(10.0, float(settings.report_lease_seconds))
        self.timeout = max(1.0, float(settings.report_timeout_seconds))
        self.last_beat = time.monotonic()
        self.current: str | None = None
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ queue
    async def claim(self) -> uuid.UUID | None:
        nxt = (select(Report.id).where(Report.status == "queued").order_by(Report.created_at, Report.id)
               .limit(1).with_for_update(skip_locked=True).scalar_subquery())
        ts = now()
        async with self.sm() as s, s.begin():
            rid = (await s.execute(
                update(Report).where(Report.id == nxt)
                .values(status="running", worker_id=self.worker_id, attempts=Report.attempts + 1,
                        started_at=func.coalesce(Report.started_at, ts), heartbeat_at=ts,
                        leased_until=ts + timedelta(seconds=self.lease), error=None)
                .returning(Report.id)
            )).scalar_one_or_none()
        return rid

    async def requeue_expired(self) -> int:
        """Rows whose lease ran out (their worker died). Rows from before the lease columns
        existed (`leased_until` NULL) count as expired one lease after they were created."""
        ts = now()
        expired = func.coalesce(Report.leased_until, Report.created_at + timedelta(seconds=self.lease)) < ts
        exhausted = Report.attempts >= self.s.report_max_attempts
        async with self.sm() as s, s.begin():
            rows = (await s.execute(
                update(Report).where(Report.status == "running", expired)
                .values(status=case((exhausted, "failed"), else_="queued"),
                        error=case((exhausted, "report worker stopped while generating (lease expired "
                                               f"{self.s.report_max_attempts} times); generate it again"),
                                   else_=Report.error),
                        finished_at=case((exhausted, ts), else_=None), leased_until=None, worker_id=None)
                .returning(Report.id, Report.status)
            )).all()
        for rid, status in rows:
            log.warning("report.lease_expired", report_id=str(rid), status=status)
        return len(rows)

    async def heartbeat(self, rid: uuid.UUID) -> bool:
        ts = now()
        async with self.sm() as s, s.begin():
            res = await s.execute(
                update(Report).where(Report.id == rid, Report.status == "running", Report.worker_id == self.worker_id)
                .values(heartbeat_at=ts, leased_until=ts + timedelta(seconds=self.lease)))
        self.last_beat = time.monotonic()
        return bool(res.rowcount)

    async def _heartbeat_loop(self, rid: uuid.UUID) -> None:
        while True:
            await asyncio.sleep(self.lease / 3)
            try:
                await self.heartbeat(rid)
            except Exception:  # noqa: BLE001  (DB blip: the next beat or the lease covers it)
                log.warning("report.heartbeat_failed", report_id=str(rid))

    # ------------------------------------------------------------- generation
    async def _generate_child(self, rid: uuid.UUID) -> str:
        argv = [sys.executable, "-m", "posture.report_worker", "--generate", str(rid), "--worker-id", self.worker_id]
        proc = await asyncio.create_subprocess_exec(*argv, env=child_env(), stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.DEVNULL,
                                                    stderr=asyncio.subprocess.PIPE)
        try:
            _, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except (TimeoutError, asyncio.TimeoutError):
            proc.kill()
            await proc.wait()
            await report_jobs.mark_failed(self.sm, rid, f"timed out after {int(self.timeout)}s "
                                                        "(REPORT_TIMEOUT_SECONDS)", self.worker_id)
            return "failed"
        except asyncio.CancelledError:
            proc.kill()
            await proc.wait()
            raise
        if proc.returncode != 0:
            tail = (err or b"").decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            reason = ("killed (out of memory?)" if proc.returncode in (-9, 137)
                      else f"generator exited with code {proc.returncode}")
            await report_jobs.mark_failed(self.sm, rid, f"{reason}: {tail[0][:500]}".rstrip(": "), self.worker_id)
            return "failed"
        async with self.sm() as s:
            row = await s.get(Report, rid)
        return row.status if row is not None else "missing"

    async def _generate_inline(self, rid: uuid.UUID) -> str:
        try:
            return await asyncio.wait_for(report_jobs.generate(self.sm, rid, self.worker_id), timeout=self.timeout)
        except (TimeoutError, asyncio.TimeoutError):
            await report_jobs.mark_failed(self.sm, rid, f"timed out after {int(self.timeout)}s "
                                                        "(REPORT_TIMEOUT_SECONDS)", self.worker_id)
            return "failed"

    async def process(self, rid: uuid.UUID) -> str:
        async with self.sm() as s:
            row = await s.get(Report, rid)
            rtype = row.type if row is not None else "unknown"
        self.current = str(rid)
        started = time.monotonic()
        beat = asyncio.create_task(self._heartbeat_loop(rid))
        try:
            if self.isolation == "inline":
                status = await self._generate_inline(rid)
            else:
                status = await self._generate_child(rid)
        except asyncio.CancelledError:
            await report_jobs.mark_failed(self.sm, rid, "report worker shutting down; generate it again",
                                          self.worker_id)
            raise
        except Exception as e:  # noqa: BLE001
            log.exception("report.worker_error", report_id=str(rid))
            await report_jobs.mark_failed(self.sm, rid, f"report worker error: {e}"[:2000], self.worker_id)
            status = "failed"
        finally:
            beat.cancel()
            self.current = None
        metrics.REPORT_DURATION.labels(rtype, status).observe(time.monotonic() - started)
        metrics.REPORTS_GENERATED.labels(rtype, status).inc()
        log.info("report.processed", report_id=str(rid), type=rtype, status=status,
                 duration_ms=int((time.monotonic() - started) * 1000))
        try:
            await report_jobs.prune(self.sm)
        except Exception:  # noqa: BLE001
            log.exception("report.prune_failed")
        return status

    async def poll_once(self) -> bool:
        self.last_beat = time.monotonic()
        await self.requeue_expired()
        rid = await self.claim()
        if rid is None:
            return False
        await self.process(rid)
        return True

    async def drain(self, limit: int = 1000) -> int:
        """Process queued reports until none is left (tests, one-shot runs)."""
        n = 0
        while n < limit and await self.poll_once():
            n += 1
        return n

    async def run_forever(self, refresh_metrics: bool = True) -> None:
        log.info("report_worker.ready", worker_id=self.worker_id, isolation=self.isolation,
                 timeout_s=self.timeout, lease_s=self.lease)
        last_metrics = 0.0
        while not self._stop.is_set():
            try:
                ran = await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("report_worker.loop_error")
                ran = False
            if refresh_metrics and time.monotonic() - last_metrics > 30:
                last_metrics = time.monotonic()
                async with self.sm() as s:
                    await metrics.refresh_db_gauges(s)
            if not ran:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.s.worker_poll_seconds)
                except (TimeoutError, asyncio.TimeoutError):
                    pass

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------- process entry points
def health_app(worker: ReportWorker):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, Response

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz():
        age = round(time.monotonic() - worker.last_beat, 1)
        # a report in progress beats through its lease heartbeat
        ok = age < max(300.0, worker.timeout + worker.lease)
        return JSONResponse({"status": "ok" if ok else "stale", "lastHeartbeatAgeSeconds": age,
                             "current": worker.current}, status_code=200 if ok else 503)

    @app.get("/metrics")
    async def prom():
        body, ctype = metrics.exposition()
        return Response(body, media_type=ctype)

    return app


async def _wait_for_db(sm: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    delay = 2.0
    while not stop.is_set():
        try:
            async with sm() as s:
                await s.execute(text("SELECT 1"))
            return
        except Exception as e:  # noqa: BLE001
            log.warning("report_worker.db_unavailable", error=str(e)[:200])
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 30)


async def _serve() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)
    from .db.session import get_sessionmaker

    sm = get_sessionmaker()
    worker = ReportWorker(settings, sm)
    import uvicorn

    port = int(os.environ.get("WORKER_HEALTH_PORT", "9000"))
    server = uvicorn.Server(uvicorn.Config(health_app(worker), host="0.0.0.0", port=port, log_config=None,
                                           access_log=False, lifespan="off"))
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    loop = asyncio.get_running_loop()

    async def main() -> None:
        await _wait_for_db(sm, worker._stop)
        await worker.run_forever()

    main_task = asyncio.create_task(main())

    def _shutdown() -> None:
        log.info("report_worker.stopping")
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
        log.info("report_worker.stopped")


async def _generate_one(report_id: str, worker_id: str | None) -> int:
    settings = get_settings()
    setup_logging(settings.log_level)
    from .db.session import dispose_engine, get_sessionmaker

    try:
        status = await report_jobs.generate(get_sessionmaker(), report_id, worker_id)
    finally:
        await dispose_engine()
    return 0 if status in ("done", "failed", "missing") else 3


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m posture.report_worker")
    ap.add_argument("--generate", metavar="REPORT_ID", help="generate one claimed report and exit (child mode)")
    ap.add_argument("--worker-id", default=None)
    args = ap.parse_args(argv)
    if args.generate:
        sys.exit(asyncio.run(_generate_one(args.generate, args.worker_id)))
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
