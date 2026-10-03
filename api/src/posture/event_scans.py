"""Pod watcher: targeted scans for new image digests (architecture review m11).

With only the interval schedule (6 h) a new workload can run unscanned for hours. The scan
worker watches pods cluster-wide (the ClusterRole already grants `watch`); when a container
reports an image key (`repo@digest` from its imageID) that no scan has seen, the key is
collected and, debounced, a namespace-targeted scan is queued:

* the first new key starts a window; the scan is queued when no further new key arrived for
  `quiet` seconds (10) or at the latest `EVENT_SCAN_DEBOUNCE_SECONDS` (60) after the first,
  so a rollout of 20 pods produces one scan within a minute;
* the scan (`trigger=event`, `target_namespaces` = the namespaces of the new pods) runs the
  normal inventory and scans only images that are not fresh, i.e. the new digests; a queued
  event scan absorbs further namespaces; a queued full scan makes it unnecessary;
* event scans do not count as full scans for the schedule and skip auto-generated reports.

`EVENT_SCANS_ENABLED=false` turns it off. The daily full sweep stays the safety net.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from sqlalchemy import select

from .db.models import Image, Scan
from .images import identify_image
from .logs import get_logger

log = get_logger(__name__)

EVENT_TRIGGER = "event"
STATUS_KEYS = ("containerStatuses", "initContainerStatuses")


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
    def __init__(self, sessionmaker: Any, excluded_namespaces: Callable[[], Iterable[str]] | None = None,
                 stream_factory: Callable[[threading.Event], Iterable[dict[str, Any]]] | None = None,
                 debounce: float = 60, quiet: float = 10):
        self.sm = sessionmaker
        self.excluded = excluded_namespaces or (lambda: ())
        self.stream_factory = stream_factory or kube_pod_stream
        self.debounce = max(0.0, debounce)
        self.quiet = min(quiet, self.debounce) if self.debounce else 0.0
        self.known: set[str] = set()
        self.pending: dict[str, str] = {}
        self._first = 0.0
        self._last = 0.0
        self._stop = threading.Event()
        self.queued: list[int] = []

    async def load_known(self) -> None:
        async with self.sm() as s:
            self.known = {k for (k,) in (await s.execute(
                select(Image.key).where(Image.last_scanned_at.isnot(None)))).all()}

    def observe(self, event: dict[str, Any]) -> int:
        """Collect new keys from one watch event; returns how many were new."""
        if event.get("type") not in ("ADDED", "MODIFIED"):
            return 0
        excluded = set(self.excluded())
        new = 0
        for key, ns in pod_image_keys(event.get("object")):
            if ns in excluded or key in self.known or key in self.pending:
                continue
            if not self.pending:
                self._first = time.monotonic()
            self.pending[key] = ns
            self._last = time.monotonic()
            new += 1
        return new

    def due(self, now: float | None = None) -> bool:
        if not self.pending:
            return False
        now = time.monotonic() if now is None else now
        return now - self._last >= self.quiet or now - self._first >= self.debounce

    async def flush(self) -> int | None:
        """Queue (or extend) one namespace-targeted scan for the pending keys."""
        if not self.pending:
            return None
        async with self.sm() as s:  # scanned meanwhile (e.g. by a full scan): nothing to do
            done = {k for (k,) in (await s.execute(select(Image.key).where(
                Image.key.in_(list(self.pending)), Image.last_scanned_at.isnot(None)))).all()}
        self.known.update(done)
        for k in done:
            self.pending.pop(k, None)
        if not self.pending:
            return None
        namespaces = sorted(set(self.pending.values()))
        keys = list(self.pending)
        self.pending.clear()
        scan_id = await enqueue_event_scan(self.sm, namespaces)
        self.known.update(keys)  # one scan per new digest; a failed scan falls back to the schedule
        if scan_id is not None:
            from . import metrics

            metrics.EVENT_SCANS.inc()
            self.queued.append(scan_id)
        log.info("event_scan.queued", scan_id=scan_id, namespaces=",".join(namespaces), digests=len(keys))
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
    queued full scan will cover them anyway. Returns the scan id (None when skipped)."""
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
