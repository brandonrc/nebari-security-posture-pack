"""Pod watcher: targeted scans for new image digests (architecture review m11).

With only the interval schedule (6 h) a new workload can run unscanned for hours. The scan
worker watches pods cluster-wide (the ClusterRole already grants `watch`); when a container
reports an image key (`repo@digest` from its imageID) that no scan has seen, the key is
collected and, debounced, a namespace-targeted scan is queued:

* the first new key starts a window; the scan is queued when no further new key arrived for
  `quiet` seconds (10) or at the latest `EVENT_SCAN_DEBOUNCE_SECONDS` (60) after the first,
  so a rollout of 20 pods produces one scan within a minute;
* at most one event scan per `EVENT_SCANS_DEBOUNCE_SECONDS` (300), across namespaces: keys
  that arrive meanwhile wait and go into the next one;
* hygiene (grace, 2026-10-05): pods owned by a Job (CronJob runs, e.g. a nightly
  `postgresql:latest` backup) are ignored unless `EVENT_SCANS_INCLUDE_JOBS=true`; pods that
  already terminated are ignored; a pod younger than `EVENT_SCANS_MIN_POD_AGE_SECONDS` (120)
  is held until it reaches that age and dropped when it is deleted first, so short-lived
  verify pods never trigger a scan;
* never while a full scan is in flight: a queued full scan absorbs the keys (its inventory
  will see them), a running one defers them until it finished (the keys it scanned are
  dropped, the rest go into one event scan);
* the scan (`trigger=event`, `target_namespaces` = the namespaces of the new pods) runs the
  normal inventory and scans only images that are not fresh, i.e. the new digests; a queued
  event scan absorbs further namespaces;
* event scans do not count as full scans for the schedule, never auto-generate reports and run
  the controls engine only when the posture-relevant inventory changed (posture.worker).

`EVENT_SCANS_ENABLED=false` turns it off. The scheduled full sweep stays the safety net.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from .db.models import Image, Scan
from .images import identify_image
from .logs import get_logger

log = get_logger(__name__)

EVENT_TRIGGER = "event"
STATUS_KEYS = ("containerStatuses", "initContainerStatuses")
JOB_OWNER_KINDS = frozenset({"Job", "CronJob"})
TERMINAL_PHASES = frozenset({"Succeeded", "Failed"})
FULL_SCAN_RUNNING = ("running", "scanned", "finalizing")  # views.ACTIVE_SCAN_STATUSES minus queued
DEFER_RETRY_SECONDS = 30.0  # re-check a running full scan this often while keys wait


def _get(obj: Any, key: str, attr: str | None = None) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, attr or key, None)


def pod_image_keys(pod: Any) -> list[tuple[str, str]]:
    """(image key, namespace) for every started container of a pod (dict or V1Pod)."""
    meta = _get(pod, "metadata")
    ns = _get(meta, "namespace") or ""
    status = _get(pod, "status")
    out = []
    for key, attr in zip(STATUS_KEYS, ("container_statuses", "init_container_statuses"), strict=True):
        for cs in _get(status, key, attr) or []:
            image_id = _get(cs, "imageID", "image_id")
            image = _get(cs, "image") or ""
            if not image_id:
                continue  # not pulled yet: the next MODIFIED event carries it
            ident = identify_image(image, image_id)
            if "@" in ident.key:
                out.append((ident.key, ns))
    return out


def pod_owned_by_job(pod: Any) -> bool:
    """CronJob runs: the pod's controller is a Job (a bare pod of a CronJob is owned by its Job)."""
    meta = _get(pod, "metadata")
    for ref in _get(meta, "ownerReferences", "owner_references") or []:
        if _get(ref, "kind") in JOB_OWNER_KINDS:
            return True
    return False


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def pod_age_seconds(pod: Any, now: datetime | None = None) -> float | None:
    """Seconds since `metadata.creationTimestamp` (None when the pod carries none)."""
    created = _parse_ts(_get(_get(pod, "metadata"), "creationTimestamp", "creation_timestamp"))
    if created is None:
        return None
    return max(0.0, ((now or datetime.now(UTC)) - created).total_seconds())


def _pod_id(pod: Any) -> str:
    meta = _get(pod, "metadata")
    return str(_get(meta, "uid") or f"{_get(meta, 'namespace') or ''}/{_get(meta, 'name') or ''}")


def kube_pod_stream(stop: threading.Event) -> Iterator[dict[str, Any]]:
    """Blocking pod watch (all namespaces), re-established every 5 min; yields dict events."""
    from kubernetes import client, watch
    from kubernetes.client import ApiClient

    from .inventory import _load_kube_config

    _load_kube_config()
    core = client.CoreV1Api()
    api = ApiClient()
    while not stop.is_set():
        w = watch.Watch()
        for ev in w.stream(core.list_pod_for_all_namespaces, timeout_seconds=300):
            if stop.is_set():
                w.stop()
                return
            yield {"type": ev.get("type"), "object": api.sanitize_for_serialization(ev.get("object"))}


class PodWatcher:
    """`debounce` = collection window after the first new key (EVENT_SCAN_DEBOUNCE_SECONDS);
    `interval` = minimum time between two queued event scans (EVENT_SCANS_DEBOUNCE_SECONDS);
    `min_pod_age` = EVENT_SCANS_MIN_POD_AGE_SECONDS; `include_jobs` = EVENT_SCANS_INCLUDE_JOBS.
    The defaults keep the plain behaviour (tests); the worker passes the settings."""

    def __init__(self, sessionmaker: Any, excluded_namespaces: Callable[[], Iterable[str]] | None = None,
                 stream_factory: Callable[[threading.Event], Iterable[dict[str, Any]]] | None = None,
                 debounce: float = 60, quiet: float = 10, interval: float = 0.0, min_pod_age: float = 0.0,
                 include_jobs: bool = True):
        self.sm = sessionmaker
        self.excluded = excluded_namespaces or (lambda: ())
        self.stream_factory = stream_factory or kube_pod_stream
        self.debounce = max(0.0, debounce)
        self.quiet = min(quiet, self.debounce) if self.debounce else 0.0
        self.interval = max(0.0, interval)
        self.min_pod_age = max(0.0, min_pod_age)
        self.include_jobs = include_jobs
        self.known: set[str] = set()
        self.pending: dict[str, str] = {}
        self.young: dict[str, tuple[float, list[tuple[str, str]]]] = {}  # pod id -> (ready at, keys)
        self.ignored: dict[str, int] = {"job": 0, "terminated": 0, "young": 0}
        self._first = 0.0
        self._last = 0.0
        self._last_flush: float | None = None
        self._retry_at = 0.0
        self._stop = threading.Event()
        self.queued: list[int] = []

    async def load_known(self) -> None:
        async with self.sm() as s:
            self.known = {k for (k,) in (await s.execute(
                select(Image.key).where(Image.last_scanned_at.isnot(None)))).all()}

    def _add(self, key: str, ns: str, mono: float) -> bool:
        if key in self.known or key in self.pending:
            return False
        if not self.pending:
            self._first = mono
        self.pending[key] = ns
        self._last = mono
        return True

    def observe(self, event: dict[str, Any], now: float | None = None, wall: datetime | None = None) -> int:
        """Collect new keys from one watch event; returns how many became pending now."""
        mono = time.monotonic() if now is None else now
        pod = event.get("object")
        etype = event.get("type")
        if etype == "DELETED":
            self.young.pop(_pod_id(pod), None)  # gone before it was old enough: never scanned for it
            return 0
        if etype not in ("ADDED", "MODIFIED"):
            return 0
        if not self.include_jobs and pod_owned_by_job(pod):
            self.ignored["job"] += 1
            return 0
        if _get(_get(pod, "status"), "phase") in TERMINAL_PHASES:
            self.young.pop(_pod_id(pod), None)
            self.ignored["terminated"] += 1
            return 0
        excluded = set(self.excluded())
        keys = [(k, ns) for k, ns in pod_image_keys(pod)
                if ns not in excluded and k not in self.known and k not in self.pending]
        if not keys:
            return 0
        if self.min_pod_age:
            age = pod_age_seconds(pod, wall)
            if age is not None and age < self.min_pod_age:
                pid = _pod_id(pod)
                ready = self.young.get(pid, (mono + self.min_pod_age - age, []))[0]
                merged = list(dict.fromkeys([*self.young.get(pid, (0.0, []))[1], *keys]))
                self.young[pid] = (ready, merged)
                self.ignored["young"] += 1
                return 0
        return sum(1 for k, ns in keys if self._add(k, ns, mono))

    def promote(self, now: float | None = None) -> int:
        """Young pods that lived long enough (no DELETED / terminal event meanwhile) -> pending."""
        mono = time.monotonic() if now is None else now
        new = 0
        for pid, (ready, keys) in list(self.young.items()):
            if ready <= mono:
                del self.young[pid]
                new += sum(1 for k, ns in keys if self._add(k, ns, mono))
        return new

    def due(self, now: float | None = None) -> bool:
        if not self.pending:
            return False
        now = time.monotonic() if now is None else now
        if now < self._retry_at:
            return False
        if self._last_flush is not None and now - self._last_flush < self.interval:
            return False  # at most one event scan per EVENT_SCANS_DEBOUNCE_SECONDS
        return now - self._last >= self.quiet or now - self._first >= self.debounce

    async def full_scan_running(self) -> bool:
        async with self.sm() as s:
            return bool(await s.scalar(select(func.count()).select_from(Scan).where(
                Scan.status.in_(FULL_SCAN_RUNNING), Scan.target_image_ids.is_(None),
                Scan.target_namespaces.is_(None))))

    async def flush(self, now: float | None = None) -> int | None:
        """Queue (or extend) one namespace-targeted scan for the pending keys."""
        if not self.pending:
            return None
        mono = time.monotonic() if now is None else now
        async with self.sm() as s:  # scanned meanwhile (e.g. by a full scan): nothing to do
            done = {k for (k,) in (await s.execute(select(Image.key).where(
                Image.key.in_(list(self.pending)), Image.last_scanned_at.isnot(None)))).all()}
        self.known.update(done)
        for k in done:
            self.pending.pop(k, None)
        if not self.pending:
            return None
        if await self.full_scan_running():
            self._retry_at = mono + DEFER_RETRY_SECONDS
            log.info("event_scan.deferred", reason="full scan running", digests=len(self.pending))
            return None
        namespaces = sorted(set(self.pending.values()))
        keys = list(self.pending)
        self.pending.clear()
        self._last_flush = mono
        scan_id = await enqueue_event_scan(self.sm, namespaces)
        self.known.update(keys)  # one scan per new digest; a failed scan falls back to the schedule
        if scan_id is not None:
            from . import metrics

            metrics.EVENT_SCANS.inc()
            self.queued.append(scan_id)
        log.info("event_scan.queued", scan_id=scan_id, namespaces=",".join(namespaces), digests=len(keys),
                 merged_into_full=scan_id is None)
        return scan_id

    async def run(self) -> None:
        """Watch forever (reconnecting with backoff); the blocking stream runs in a thread."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        await self.load_known()

        def pump() -> None:
            delay = 2.0
            while not self._stop.is_set():
                try:
                    for ev in self.stream_factory(self._stop):
                        loop.call_soon_threadsafe(queue.put_nowait, ev)
                        delay = 2.0
                    if self._stop.is_set():
                        return
                except Exception as e:  # noqa: BLE001
                    log.warning("event_scan.watch_error", error=str(e)[:200])
                self._stop.wait(delay)
                delay = min(delay * 2, 60)

        thread = threading.Thread(target=pump, name="pod-watch", daemon=True)
        thread.start()
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=1.0)
                    self.observe(ev)
                except (TimeoutError, asyncio.TimeoutError):
                    pass
                self.promote()
                if self.due():
                    try:
                        await self.flush()
                    except Exception:  # noqa: BLE001
                        log.exception("event_scan.enqueue_failed")
        finally:
            self._stop.set()

    def stop(self) -> None:
        self._stop.set()


async def enqueue_event_scan(sm: Any, namespaces: list[str]) -> int | None:
    """Insert a `trigger=event` scan for `namespaces`, merge into a queued one, or skip when a
    queued full scan will cover them anyway (its inventory sees the new pods). Returns the scan
    id (None when merged into a full scan). A *running* full scan is handled by the caller
    (`PodWatcher.flush` defers the keys until it finished)."""
    async with sm() as s, s.begin():
        queued = (await s.execute(
            select(Scan).where(Scan.status == "queued", Scan.target_image_ids.is_(None))
            .order_by(Scan.id).with_for_update(skip_locked=True))).scalars().all()
        for sc in queued:
            if not sc.target_namespaces:
                return None  # a full scan is queued
        for sc in queued:
            if sc.trigger == EVENT_TRIGGER:
                sc.target_namespaces = sorted(set(sc.target_namespaces or []) | set(namespaces))
                return sc.id
        scan = Scan(trigger=EVENT_TRIGGER, status="queued", requested_by="pod-watcher", force=False,
                    target_namespaces=sorted(namespaces), per_scanner={}, log=[])
        s.add(scan)
        await s.flush()
        return scan.id
