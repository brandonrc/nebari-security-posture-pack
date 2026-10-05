"""Worker stage `scap` (DESIGN §14): image -> rootfs -> detect -> oscap per benchmark -> rows.

Who runs it:
* the `scap-worker` Deployment (`python -m posture.worker --stages scap`): root in its container
  (full rootfs fidelity), claims scans whose `scap_status` is `queued` (set by the scan worker
  when a scan's CVE stage finishes) and owns SCAP_CONTENT_DIR (daily content refresh);
* the scan worker itself with SCAP_EMBEDDED=true (dev / single process; usually non-root, so
  `rootfsFidelity: degraded`), or when the worker runs every stage (`--stages all`).

Scope per scan: the images (re)scanned by that scan plus inventory images never evaluated;
a forced full scan evaluates everything (`scans.scap_image_ids`, computed by the scan worker).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db.models import Image, ScannerStatus
from ..images import parse_image_ref
from ..logs import get_logger
from . import content as content_mod
from . import oscap as oscap_mod
from .detect import Detection, candidates_for, detect
from .models import ScapContent, ScapImageSummary, ScapResultRow
from .rootfs import RootfsError, flatten, is_root, remove_tree
from .scoring import image_stig, open_by_cat, stig_score, weights

log = get_logger(__name__)

SCANNER_NAME = "scap"
LogFn = Callable[[str], Any]


def now() -> datetime:
    return datetime.now(UTC)


@dataclass
class BenchmarkOutcome:
    candidate: dict[str, Any]
    entry: dict[str, Any] | None
    profile_id: str | None
    result: oscap_mod.EvalResult


@dataclass
class ImageOutcome:
    image_id: int
    status: str  # evaluated | notApplicable | noContent | error | timeout
    detection: Detection | None = None
    rootfs: dict[str, Any] = field(default_factory=dict)
    benchmarks: list[BenchmarkOutcome] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0


Evaluator = Callable[..., Awaitable[oscap_mod.EvalResult]]


class ScapStage:
    def __init__(self, settings: Any, sessionmaker: async_sessionmaker[AsyncSession], mirror: Any = None,
                 evaluator: Evaluator | None = None, privileged: bool | None = None):
        self.s = settings
        self.sm = sessionmaker
        self.content_dir = Path(settings.scap_content_path)
        self.work_dir = Path(settings.scap_work_path)
        if mirror is None:
            from ..mirror import Mirror

            mirror = Mirror(settings)
        self.mirror = mirror
        cache = getattr(mirror, "cache", None)
        if cache is None:  # registry / off mirror mode: the scap stage still needs a local layout
            from ..image_cache import LocalImageCache

            cache = LocalImageCache(settings, mirror)
        self.cache = cache
        self.evaluator = evaluator or oscap_mod.evaluate
        self.privileged = is_root() if privileged is None else privileged
        self.oscap_version: str | None = None
        self._last_refresh = 0.0
        self._refresh_lock = asyncio.Lock()

    # ------------------------------------------------------------------ content
    async def refresh_content(self, app: Any, force: bool = False) -> content_mod.RefreshResult | None:
        """Fetch configured sources (unless SCAP_CONTENT_OFFLINE), re-index, mirror the catalogue
        into `scap_content` and the `scanner_status` row. At most every SCAP_CONTENT_REFRESH_HOURS."""
        async with self._refresh_lock:
            due = time.monotonic() - self._last_refresh >= float(self.s.scap_content_refresh_hours) * 3600
            if not force and self._last_refresh and not due:
                return None
            sources_cfg = [src.model_dump() if hasattr(src, "model_dump") else dict(src)
                           for src in getattr(getattr(app, "scap", None), "sources", None) or self.s.scap_sources]
            errors: dict[str, str] = {}
            try:
                sources = content_mod.parse_sources(sources_cfg)
            except content_mod.ContentError as e:
                sources, errors = [], {"config": str(e)}
            res = await asyncio.to_thread(content_mod.refresh, self.content_dir, sources,
                                          bool(self.s.scap_content_offline))
            res.errors.update(errors)
            self._last_refresh = time.monotonic()
        await self._sync_catalogue(res)
        return res

    async def _sync_catalogue(self, res: content_mod.RefreshResult) -> None:
        cat = content_mod.catalogue(res.index)
        if self.oscap_version is None:
            self.oscap_version = await oscap_mod.oscap_version(self.s.oscap_bin)
        async with self.sm() as s, s.begin():
            await s.execute(delete(ScapContent))
            for e in cat:
                s.add(ScapContent(path=e["path"], file=e["file"], benchmark_id=e["benchmarkId"],
                                  datastream_id=e.get("datastreamId"), title=e["title"] or "",
                                  version=(e["version"] or "")[:128], release_info=e.get("releaseInfo") or "",
                                  status_date=(e.get("statusDate") or "")[:32], source=e["source"] or "custom",
                                  source_name=e.get("sourceName"), url=e.get("url"), sha256=e.get("sha256"),
                                  size_bytes=e.get("sizeBytes"), profiles=e["profiles"], rules=e["rules"],
                                  fetched_at=_dt(e.get("fetchedAt"))))
            row = await s.get(ScannerStatus, SCANNER_NAME)
            if row is None:
                row = ScannerStatus(name=SCANNER_NAME)
                s.add(row)
            row.version = (self.oscap_version or "")[:64] or None
            fetched = [d for d in (_dt(e.get("fetchedAt")) for e in cat) if d]
            row.db_updated_at = max(fetched) if fetched else None
            problems = [f"{k}: {v}" for k, v in res.errors.items()]
            if not cat:
                problems.append(f"no SCAP content in {self.content_dir}")
            if self.oscap_version is None:
                problems.append("oscap not found")
            row.healthy = not problems
            row.last_error = "; ".join(problems)[:2000] or None
            row.updated_at = now()
        log.info("scap.content.indexed", benchmarks=len(cat), fetched=",".join(res.fetched),
                 errors=len(res.errors))

    def _catalogue(self) -> list[dict[str, Any]]:
        return content_mod.catalogue(content_mod.load_index(self.content_dir))

    # ------------------------------------------------------------------ run
    async def run(self, scan_id: int | None, image_ids: list[int], app: Any, log_fn: LogFn | None = None,
                  cancelled: Callable[[], bool] | None = None) -> dict[str, int]:
        """Evaluate `image_ids` sequentially (each is CPU + disk heavy). Never raises for one image."""
        emit = log_fn or (lambda _m: None)
        if not (content_mod.load_index(self.content_dir).get("files")):
            await self.refresh_content(app, force=True)
        else:
            await self.refresh_content(app)
        cat = self._catalogue()
        timeout = float(getattr(getattr(app, "scap", None), "timeout_seconds", None) or self.s.scap_timeout_seconds)
        prefer_disa = bool(getattr(getattr(app, "scap", None), "prefer_disa", self.s.scap_prefer_disa))
        stats = {"evaluated": 0, "notApplicable": 0, "noContent": 0, "error": 0, "timeout": 0}
        if not image_ids:
            return stats
        emit(f"scap: evaluating {len(image_ids)} image(s) against {len(cat)} benchmark(s) "
             f"(rootfs fidelity {'full' if self.privileged else 'degraded: not root'})")
        for image_id in image_ids:
            if cancelled is not None and cancelled():
                break
            try:
                out = await self.evaluate_image(image_id, cat, timeout, prefer_disa)
            except Exception as e:  # noqa: BLE001  (one image never fails the stage)
                log.exception("scap.image_failed", image_id=image_id)
                out = ImageOutcome(image_id, "error", error=f"internal error: {e}"[:500])
            await self.persist(scan_id, out)
            stats[out.status] = stats.get(out.status, 0) + 1
            emit(self._line(out))
        await self._touch_status()
        return stats

    async def _touch_status(self) -> None:
        async with self.sm() as s, s.begin():
            row = await s.get(ScannerStatus, SCANNER_NAME)
            if row is None:
                row = ScannerStatus(name=SCANNER_NAME, healthy=True)
                s.add(row)
            row.last_run_at = now()

    @staticmethod
    def _line(out: ImageOutcome) -> str:
        if out.status == "evaluated":
            parts = []
            for b in out.benchmarks:
                c = b.result.counts
                parts.append(f"{b.candidate['key']} {b.result.status}: {c.get('pass', 0)} pass / {c.get('fail', 0)} fail"
                             f" / {c.get('notapplicable', 0)} n/a / {c.get('notchecked', 0)} notchecked")
            return f"scap image {out.image_id}: " + "; ".join(parts)
        return f"scap image {out.image_id}: {out.status}" + (f" ({out.error})" if out.error else "")

    async def _image(self, image_id: int) -> Image | None:
        async with self.sm() as s:
            return await s.get(Image, image_id)

    async def evaluate_image(self, image_id: int, cat: list[dict[str, Any]], timeout: float,
                             prefer_disa: bool = True) -> ImageOutcome:
        started = time.monotonic()
        img = await self._image(image_id)
        if img is None:
            return ImageOutcome(image_id, "error", error="image row vanished")
        ref = parse_image_ref(img.key)
        if img.tag and not ref.tag:
            ref = type(ref)(ref.registry, ref.repository, img.tag, ref.digest)
        if not ref.digest:
            return ImageOutcome(image_id, "error", error="image has no digest (locally loaded / not started); "
                                                         "a rootfs is only built from digest-pinned images")
        src, src_insecure, _ = self.mirror.plan(ref)
        try:
            layout, _digest = await self.cache.ensure(src.pullable, ref.digest, src_insecure, timeout=min(timeout, 900))
        except Exception as e:  # noqa: BLE001
            return ImageOutcome(image_id, "error", error=f"image copy failed: {str(e)[:300]}")
        hexd = ref.digest.split(":", 1)[-1]
        base = self.work_dir / hexd[:32]
        rootfs_dir = base / "rootfs"
        out = ImageOutcome(image_id, "error")
        try:
            remove_tree(base)
            max_bytes = int(float(self.s.scap_max_rootfs_gb) * 1024**3)
            try:
                rr = await asyncio.to_thread(flatten, layout, rootfs_dir, max_bytes, self.privileged)
            except RootfsError as e:
                out.error = f"rootfs: {e}"
                return out
            out.rootfs = rr.as_dict()
            det = await asyncio.to_thread(detect, rootfs_dir)
            out.detection = det
            cands = candidates_for(det, prefer_disa, extra=getattr(self.s, "scap_benchmarks_file", "") or None)
            if not cands:
                out.status = "notApplicable"
                os_label = f"{det.os.get('id', 'unknown')} {det.os.get('versionId', '')}".strip()
                out.error = (f"no SCAP benchmark applies (os {os_label or 'unknown'}"
                             + (", distroless" if det.distroless else "") + ")")
                return out
            chosen: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {}
            missing = []
            for c in cands:
                if c["family"] in chosen:
                    continue
                hit = content_mod.find_content(cat, c["datastreams"], c["profiles"])
                if hit is None:
                    missing.append(c["key"])
                    continue
                chosen[c["family"]] = (c, hit[0], hit[1])
            if not chosen:
                out.status = "noContent"
                out.error = f"no content for the applicable benchmark(s): {', '.join(missing)}"
                return out
            deadline = time.monotonic() + timeout
            for c, entry, profile in chosen.values():
                remaining = deadline - time.monotonic()
                if remaining <= 5:
                    out.benchmarks.append(BenchmarkOutcome(c, entry, profile, oscap_mod.EvalResult(
                        status="timeout", error="per-image SCAP time budget exhausted")))
                    continue
                path = self.content_dir / entry["path"]
                meta = await asyncio.to_thread(content_mod.rule_metadata, self.content_dir, path,
                                               entry.get("sha256") or "nosha", entry["benchmarkId"])
                multi = sum(1 for e in cat if e["path"] == entry["path"]) > 1
                res = await self.evaluator(rootfs_dir, path, profile, base / f"work-{c['key']}", timeout=remaining,
                                           benchmark_id=entry["benchmarkId"] if multi else None, meta=meta,
                                           chroot_bin=self.s.oscap_chroot_bin,
                                           skip_validation=bool(self.s.scap_skip_validation))
                out.benchmarks.append(BenchmarkOutcome(c, entry, profile, res))
            statuses = {b.result.status for b in out.benchmarks}
            out.status = ("evaluated" if "evaluated" in statuses else "timeout" if statuses == {"timeout"}
                          else "notApplicable" if statuses == {"notApplicable"} else "error")
            if out.status != "evaluated":
                out.error = "; ".join(f"{b.candidate['key']}: {b.result.error or b.result.status}" for b in out.benchmarks)
            return out
        finally:
            out.duration_ms = int((time.monotonic() - started) * 1000)
            await asyncio.to_thread(remove_tree, base)
            with contextlib.suppress(Exception):
                self.cache.release(str(layout))

    # ------------------------------------------------------------------ persistence
    async def persist(self, scan_id: int | None, out: ImageOutcome) -> None:
        ts = now()
        det = out.detection.as_dict() if out.detection else {}
        fidelity = out.rootfs.get("fidelity") if out.rootfs else None
        summaries: list[dict[str, Any]] = []
        async with self.sm() as s, s.begin():
            await s.execute(delete(ScapImageSummary).where(ScapImageSummary.image_id == out.image_id))
            evaluated = [b for b in out.benchmarks if b.result.status in ("evaluated", "notApplicable")]
            if out.status != "evaluated" or not evaluated:
                s.add(ScapImageSummary(
                    image_id=out.image_id, scan_id=scan_id, benchmark_key="", title="", version="", status=out.status,
                    counts={}, cat1_open=0, cat2_open=0, cat3_open=0, evaluated_weight=0.0, failed_weight=0.0,
                    score=None, rootfs_fidelity=fidelity, rootfs=out.rootfs, detected=det, error=out.error,
                    duration_ms=out.duration_ms, oscap_version=self.oscap_version, evaluated_at=ts))
                summaries.append({"status": out.status, "error": out.error})
            for b in out.benchmarks if out.status == "evaluated" else []:
                r = b.result
                status = r.status
                pairs = [(x.severity, x.result) for x in r.rules]
                ev_w, fl_w = weights(pairs)
                opened = open_by_cat(pairs)
                e = b.entry or {}
                summ = ScapImageSummary(
                    image_id=out.image_id, scan_id=scan_id, benchmark_key=b.candidate["key"],
                    benchmark_id=e.get("benchmarkId") or r.benchmark_id, title=e.get("title") or b.candidate.get("title", ""),
                    version=(e.get("version") or "")[:128], source=e.get("source") or b.candidate.get("source"),
                    profile_id=b.profile_id,
                    profile_title=next((p.get("title") for p in e.get("profiles", []) if p.get("id") == b.profile_id), None),
                    content_path=e.get("path"), content_sha256=e.get("sha256"), status=status, counts=r.counts or {},
                    cat1_open=opened["cat1Open"], cat2_open=opened["cat2Open"], cat3_open=opened["cat3Open"],
                    evaluated_weight=ev_w, failed_weight=fl_w, score=stig_score(pairs), rootfs_fidelity=fidelity,
                    rootfs=out.rootfs, detected={**det, **({"product": b.candidate["product"]} if b.candidate.get("product") else {})},
                    oscap_version=self.oscap_version, duration_ms=r.duration_ms, error=r.error, evaluated_at=ts)
                s.add(summ)
                await s.flush()
                if r.rules:
                    await s.execute(ScapResultRow.__table__.insert(), [{
                        "summary_id": summ.id, "image_id": out.image_id, "scan_id": scan_id,
                        "benchmark_key": b.candidate["key"], "rule_id": x.rule_id[:2000],
                        "stig_id": (x.stig_id or None) and x.stig_id[:64], "vuln_id": (x.vuln_id or None) and x.vuln_id[:32],
                        "sv_id": (x.sv_id or None) and x.sv_id[:64],
                        "rule_version": (x.rule_version or None) and x.rule_version[:64], "cci": x.cci, "nist": x.nist,
                        "severity": x.severity, "result": x.result, "title": x.title or x.rule_id,
                        "fix_text": x.fix_text, "group_title": x.group_title, "checked_at": ts} for x in r.rules])
                summaries.append({"status": status, "benchmarkKey": b.candidate["key"],
                                  "evaluatedWeight": ev_w, "failedWeight": fl_w, "rootfsFidelity": fidelity,
                                  **(r.counts or {}), **opened})
            img = await s.get(Image, out.image_id, with_for_update=True)
            if img is not None:
                stig = image_stig(summaries)
                stig["evaluatedAt"] = ts.isoformat().replace("+00:00", "Z")
                if out.detection:
                    stig["os"] = out.detection.os.get("prettyName") or out.detection.os.get("id")
                img.stig = stig  # type: ignore[attr-defined]


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


async def never_evaluated(session: AsyncSession, image_ids: list[int]) -> list[int]:
    """Images of `image_ids` without any scap_image_summary row."""
    if not image_ids:
        return []
    seen = {i for (i,) in (await session.execute(
        select(ScapImageSummary.image_id).where(ScapImageSummary.image_id.in_(image_ids)).distinct())).all()}
    return [i for i in image_ids if i not in seen]


def cleanup_work_dir(work_dir: Path) -> None:
    """Leftover rootfs trees of a crashed run (startup)."""
    if work_dir.exists():
        for d in work_dir.iterdir():
            if d.is_dir():
                remove_tree(d)

