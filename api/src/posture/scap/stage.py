"""Worker stage `scap` (DESIGN §14): image -> rootfs -> detect -> oscap per benchmark -> rows.

Who runs it:
* the `scap-worker` Deployment (`python -m posture.worker --stages scap`): root in its container
  (full rootfs fidelity), claims scans whose `scap_status` is `queued` (set by the scan worker
  when a scan's CVE stage finishes) and owns SCAP_CONTENT_DIR (daily content refresh);
* the scan worker itself with SCAP_EMBEDDED=true (dev / single process; usually non-root, so
  `rootfsFidelity: degraded`), or when the worker runs every stage (`--stages all`).

Scope per scan (`scans.scap_image_ids`, computed by the scan worker, `needs_evaluation`): the
images (re)scanned by that scan plus inventory images never evaluated, whose last attempt left a
stale result, or that were evaluated against other content (content fingerprint); a forced full
scan evaluates everything.

Images are evaluated SCAP_PARALLELISM at a time (oscap is single-threaded; each evaluation needs
up to ~1.1 GiB, so the effective parallelism is capped by the container memory limit).

A transient failure (image copy rate-limited / timed out, oscap timeout, internal error) never
replaces a genuine stored result (evaluated / notApplicable / noContent): the previous result is
kept and marked `stale` with the error, and the image is retried by the next scan.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
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
from .rootfs import RootfsError, flatten, is_root, prepare_for_oscap, remove_tree, secure_join
from .scoring import image_stig, open_by_cat, stig_score, weights

log = get_logger(__name__)

SCANNER_NAME = "scap"
LogFn = Callable[[str], Any]
ProgressFn = Callable[[int, int], Awaitable[Any]]
GENUINE = ("evaluated", "notApplicable", "noContent")  # outcomes that may replace a stored result
CGROUP_MEMORY_MAX = Path("/sys/fs/cgroup/memory.max")
NO_DIGEST = "image has no digest"  # permanent until the image row gets a digest: not retried every scan
MEMORY_RESERVE_MB = 384  # the worker process itself (python, skopeo, rootfs flattening)


def effective_parallelism(requested: int, memory_limit_bytes: int | None, per_eval_mb: int,
                          reserve_mb: int = MEMORY_RESERVE_MB) -> int:
    """SCAP_PARALLELISM capped by what the memory limit holds (`per_eval_mb` per oscap run)."""
    n = max(1, int(requested or 1))
    if memory_limit_bytes and per_eval_mb > 0:
        fits = (memory_limit_bytes // (1024 * 1024) - reserve_mb) // per_eval_mb
        n = min(n, max(1, int(fits)))
    return n


def memory_limit_bytes(path: Path = CGROUP_MEMORY_MAX) -> int | None:
    """cgroup v2 memory limit of this container (None = unlimited / unknown)."""
    try:
        raw = path.read_text().strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() else None


def content_fingerprint(entries: list[dict[str, Any]]) -> str | None:
    """Identity of the SCAP content set (catalogue entries or `scap_content` rows as dicts with
    path / benchmarkId / sha256 / sizeBytes). None without content. A changed fingerprint makes
    every image due for re-evaluation (DESIGN §14)."""
    rows = sorted({(str(e.get("path") or ""), str(e.get("benchmarkId") or ""), str(e.get("sha256") or ""),
                    str(e.get("sizeBytes") or "")) for e in entries})
    if not rows:
        return None
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()[:16]


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
        self.fingerprint: str | None = None  # content fingerprint of the current run
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
    def parallelism(self) -> int:
        return effective_parallelism(int(getattr(self.s, "scap_parallelism", 1) or 1), memory_limit_bytes(),
                                     int(getattr(self.s, "scap_memory_per_eval_mb", 1152) or 0))

    async def run(self, scan_id: int | None, image_ids: list[int], app: Any, log_fn: LogFn | None = None,
                  cancelled: Callable[[], bool] | None = None, progress: ProgressFn | None = None) -> dict[str, int]:
        """Evaluate `image_ids`, `parallelism()` at a time (each is CPU + disk heavy; oscap itself
        is single-threaded). Never raises for one image. `progress(done, total)` after each image."""
        emit = log_fn or (lambda _m: None)
        if not (content_mod.load_index(self.content_dir).get("files")):
            await self.refresh_content(app, force=True)
        else:
            await self.refresh_content(app)
        cat = self._catalogue()
        self.fingerprint = content_fingerprint(cat)
        timeout = float(getattr(getattr(app, "scap", None), "timeout_seconds", None) or self.s.scap_timeout_seconds)
        prefer_disa = bool(getattr(getattr(app, "scap", None), "prefer_disa", self.s.scap_prefer_disa))
        stats = {"evaluated": 0, "notApplicable": 0, "noContent": 0, "error": 0, "timeout": 0, "stale": 0}
        image_ids = list(dict.fromkeys(image_ids))
        if not image_ids:
            return stats
        par = min(self.parallelism(), len(image_ids))
        emit(f"scap: evaluating {len(image_ids)} image(s) against {len(cat)} benchmark(s), {par} at a time "
             f"(rootfs fidelity {'full' if self.privileged else 'degraded: not root'})")
        sem = asyncio.Semaphore(par)
        done = 0
        total = len(image_ids)

        async def one(image_id: int) -> None:
            nonlocal done
            async with sem:
                if cancelled is not None and cancelled():
                    return
                try:
                    out = await self.evaluate_image(image_id, cat, timeout, prefer_disa)
                except Exception as e:  # noqa: BLE001  (one image never fails the stage)
                    log.exception("scap.image_failed", image_id=image_id)
                    out = ImageOutcome(image_id, "error", error=f"internal error: {e}"[:500])
                kept = await self.persist(scan_id, out)
            stats[out.status] = stats.get(out.status, 0) + 1
            if kept:
                stats["stale"] += 1
            done += 1
            emit(self._line(out) + (" (previous result kept, marked stale)" if kept else ""))
            if progress is not None:
                with contextlib.suppress(Exception):
                    await progress(done, total)

        await asyncio.gather(*(one(i) for i in image_ids))
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

    def _source(self, img: Image, ref: Any) -> tuple[str, str, bool]:
        """(ref to copy, digest it must verify against, insecure). With MIRROR_MODE=registry the
        scan stage already copied the digest into the mirror (verified against the source digest),
        so the scap stage copies that one instead of pulling upstream again (rate limits)."""
        mref = getattr(img, "mirror_ref", None)
        if (getattr(self.mirror, "mode", None) == "registry" and img.mirrored and mref and "@sha256:" in mref
                and "oci-dir:" not in mref):
            return mref, mref.rsplit("@", 1)[1], bool(getattr(self.s, "mirror_insecure", True))
        src, src_insecure, _ = self.mirror.plan(ref)
        return src.pullable, ref.digest, src_insecure

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
            return ImageOutcome(image_id, "error", error=f"{NO_DIGEST} (locally loaded / not started); "
                                                         "a rootfs is only built from digest-pinned images")
        source, source_digest, src_insecure = self._source(img, ref)
        try:
            layout, _digest = await self.cache.ensure(source, source_digest, src_insecure, timeout=min(timeout, 900))
        except Exception as e:  # noqa: BLE001
            return ImageOutcome(image_id, "error", error=f"image copy failed: {str(e)[:300]}")
        hexd = ref.digest.split(":", 1)[-1]
        base = self.work_dir / f"{hexd[:32]}-{image_id}"  # concurrent evaluations never share a tree
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
            det = await asyncio.to_thread(detect, rootfs_dir)  # before prepare_for_oscap touches the tree
            out.detection = det
            rr.notes += await asyncio.to_thread(prepare_for_oscap, rootfs_dir)
            out.rootfs = rr.as_dict()
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
                # a dpkginfo test in RPM content (DISA benchmarks carry a few) on an image without dpkg
                # is not a probe failure that matters
                if not secure_join(rootfs_dir, "var/lib/dpkg", follow_final=True).is_dir():
                    res.warnings = [w for w in res.warnings if not w.startswith("dpkginfo")]
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
    async def persist(self, scan_id: int | None, out: ImageOutcome) -> bool:
        """Store one outcome. Returns True when it was not genuine (error / timeout) and a genuine
        previous result was kept instead (marked `stale` with this error; retried next scan)."""
        ts = now()
        det = out.detection.as_dict() if out.detection else {}
        fidelity = out.rootfs.get("fidelity") if out.rootfs else None
        summaries: list[dict[str, Any]] = []
        if out.status not in GENUINE and await self._keep_previous(out, ts):
            return True
        async with self.sm() as s, s.begin():
            first_failed = {(k, rid): t for k, rid, t in (await s.execute(
                select(ScapResultRow.benchmark_key, ScapResultRow.rule_id, ScapResultRow.first_failed_at).where(
                    ScapResultRow.image_id == out.image_id, ScapResultRow.result == "fail"))).all()}
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
                    oscap_version=self.oscap_version, duration_ms=r.duration_ms,
                    error="; ".join([*([r.error] if r.error else []), *r.warnings]) or None, evaluated_at=ts)
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
                        "fix_text": x.fix_text, "group_title": x.group_title, "checked_at": ts,
                        "first_failed_at": (first_failed.get((b.candidate["key"], x.rule_id)) or ts)
                        if x.result == "fail" else None} for x in r.rules])
                summaries.append({"status": status, "benchmarkKey": b.candidate["key"],
                                  "evaluatedWeight": ev_w, "failedWeight": fl_w, "rootfsFidelity": fidelity,
                                  **(r.counts or {}), **opened})
            img = await s.get(Image, out.image_id, with_for_update=True)
            if img is not None:
                stig = image_stig(summaries)
                stig["evaluatedAt"] = ts.isoformat().replace("+00:00", "Z")
                if out.detection:
                    stig["os"] = out.detection.os.get("prettyName") or out.detection.os.get("id")
                if self.fingerprint:
                    stig["content"] = self.fingerprint
                img.stig = stig  # type: ignore[attr-defined]
        return False

    async def _keep_previous(self, out: ImageOutcome, ts: datetime) -> bool:
        """A transient failure over a genuine stored result: keep that result, flag it stale."""
        async with self.sm() as s, s.begin():
            img = await s.get(Image, out.image_id, with_for_update=True)
            prev = dict(getattr(img, "stig", None) or {}) if img is not None else {}
            if prev.get("status") not in GENUINE:
                return False
            has_rows = await s.scalar(select(ScapImageSummary.id).where(
                ScapImageSummary.image_id == out.image_id).limit(1))
            if has_rows is None:
                return False
            prev.update({"stale": True, "staleError": (out.error or out.status)[:500],
                         "staleStatus": out.status, "staleSince": prev.get("staleSince") or
                         ts.isoformat().replace("+00:00", "Z")})
            img.stig = prev  # type: ignore[union-attr]
        log.warning("scap.result_kept_stale", image_id=out.image_id, status=out.status, error=(out.error or "")[:200])
        return True


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


async def db_content_fingerprint(session: AsyncSession) -> str | None:
    """`content_fingerprint` of the catalogue the scap-worker mirrored into `scap_content`."""
    rows = (await session.execute(select(ScapContent.path, ScapContent.benchmark_id, ScapContent.sha256,
                                         ScapContent.size_bytes))).all()
    return content_fingerprint([{"path": p, "benchmarkId": b, "sha256": h, "sizeBytes": n} for p, b, h, n in rows])


async def needs_evaluation(session: AsyncSession, image_ids: list[int]) -> dict[str, list[int]]:
    """Images of `image_ids` the scap stage must (re-)evaluate even when no scan rescanned them:
    `never` (no stored result), `retry` (the last attempt failed: a stale kept result, or an error /
    timeout with nothing better stored) and `content` (evaluated against a different content set
    than the current one)."""
    out: dict[str, list[int]] = {"never": [], "retry": [], "content": []}
    if not image_ids:
        return out
    never = set(await never_evaluated(session, image_ids))
    fp = await db_content_fingerprint(session)
    rows = (await session.execute(select(Image.id, Image.stig).where(Image.id.in_(image_ids)))).all()
    stig = {i: (d or {}) for i, d in rows}
    for i in image_ids:
        d = stig.get(i, {})
        if i in never or not d:
            out["never"].append(i)
        elif d.get("stale") or (d.get("status") in ("error", "timeout") and NO_DIGEST not in str(d.get("error") or "")):
            out["retry"].append(i)
        elif fp is not None and d.get("content") != fp:
            out["content"].append(i)
    return out


def cleanup_work_dir(work_dir: Path) -> None:
    """Leftover rootfs trees of a crashed run (startup)."""
    if work_dir.exists():
        for d in work_dir.iterdir():
            if d.is_dir():
                remove_tree(d)

