"""Worker stage `provenance` (DESIGN §12).

Runs once per scan, after inventory and concurrently with CVE scanning:
per unique image digest -> signature (+ cosign verify) / SBOM / SLSA provenance
(cached per digest for `recheckHours`) and per-tag update checks; Helm releases
from `sh.helm.release.v1.*` Secrets.

Scoping (grace, 2026-10-05): the worker passes `only` = the images (re)scanned by this scan
(None = every image: a forced full scan). Those, plus images without a usable previous result
(never checked, last check errored, check configuration changed), go to the registry; every
other image of the inventory is *carried*: its previous `image_provenance` row is copied into
this scan without a registry call, so per-scan rows and the supply-chain score still cover the
whole inventory. Persists `image_provenance` / `helm_releases`
rows for the scan plus the denormalized `images.provenance` summary, and returns
the per-image `SupplyChainInputs` the cluster aggregation needs.

Never fails the scan: every error becomes a row-level `error` / scan log line.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..app_settings import AppSettings, ProvenanceSettings
from ..config import Settings
from ..db.models import Image, Scan
from ..images import ImageRef, has_mutable_tag
from ..inventory_model import InventorySnapshot
from ..logs import get_logger
from ..scoring import grade
from . import helm as helm_mod
from .checks import (
    CosignCli,
    CosignConfig,
    CosignVerifier,
    collect_attestations,
    provenance_info,
    sbom_info,
    signature_existence,
    verify_signature,
)
from .models import HelmReleaseRow, ImageProvenance
from .registry import HttpRegistry, Registry, RegistryError, load_docker_auths
from .scoring import PENALTY_MUTABLE_TAG, SupplyChainInputs, image_penalties, inputs_from_json, provenance_controls, supply_chain_score
from .updates import UpdateInfo, compute_update, needs_tag_list
from .updates import parse_image_ref as split_tag

log = get_logger(__name__)

KEEP_SCANS = 10


def now() -> datetime:
    return datetime.now(UTC)


def config_fingerprint(ps: ProvenanceSettings) -> str:
    """Cached attestation results are only reused under the same check configuration."""
    key = json.dumps([ps.verify_signatures, ps.cosign_public_key, ps.cosign_certificate_identity_regexp,
                      ps.cosign_certificate_oidc_issuer_regexp, ps.check_sbom, ps.check_provenance])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class ImageWork:
    image_id: int
    ref: ImageRef  # registry/repo + digest (+ primary tag)
    tags: set[str] = field(default_factory=set)  # spec tags this digest runs under
    mutable: bool = False


@dataclass
class ImageOutcome:
    image_id: int
    digest: str | None
    checked_at: datetime
    signature: dict[str, Any] | None
    sbom: dict[str, Any] | None
    provenance: dict[str, Any] | None
    updates: dict[str, Any]
    details: dict[str, Any]
    error: str | None
    inputs: SupplyChainInputs
    score: float | None
    primary_tag: str | None


def work_items(inv: InventorySnapshot, key_to_id: dict[str, int], images: dict[int, Image]) -> list[ImageWork]:
    by_id: dict[int, ImageWork] = {}
    for c in inv.containers:
        iid = key_to_id.get(c.image_key or "")
        img = images.get(iid) if iid is not None else None
        if img is None:
            continue
        w = by_id.get(iid)
        if w is None:
            w = by_id[iid] = ImageWork(iid, ImageRef(img.registry_host, img.repository, img.tag, img.digest))
        _, tag = split_tag(c.image)
        w.tags.add(tag)
        w.mutable = w.mutable or has_mutable_tag(c.image)
    return [by_id[k] for k in sorted(by_id)]


def build_inputs(sig, sbom, prov, update: UpdateInfo | None, ps: ProvenanceSettings, cosign_on: bool) -> SupplyChainInputs:
    return inputs_from_json(
        sig, sbom, prov, update.as_json() if update else None,
        verification_configured=cosign_on, sbom_checked=ps.check_sbom, provenance_checked=ps.check_provenance,
        updates_checked=ps.check_updates and update is not None and needs_tag_list(update.current_tag),
        major_behind=bool(update and update.major_behind),
    )


def summary_json(o: ImageOutcome, mutable: bool) -> dict[str, Any]:
    """`ImageSummary.provenance` (camelCase; nested objects use their report shapes)."""
    deductions = [{"reason": f, "points": p} for f, p in image_penalties(o.inputs)]
    if mutable and o.score is not None:
        deductions.append({"reason": "mutable-tag", "points": PENALTY_MUTABLE_TAG})
    findings = [d["reason"] for d in deductions]
    controls: list[str] = []
    for f in findings:
        for c in provenance_controls(f):
            if c not in controls:
                controls.append(c)
    primary = (o.updates or {}).get(o.primary_tag or "") if o.primary_tag is not None else None
    return {
        "checkedAt": o.checked_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "signature": o.signature,
        "sbom": o.sbom,
        "provenance": o.provenance,
        "update": primary,
        "updates": o.updates,
        "mutableTag": mutable,
        "score": o.score,
        "grade": grade(o.score),
        "findings": findings,
        "deductions": deductions,
        "controls": controls,
        "error": o.error,
    }


class ProvenanceStage:
    def __init__(self, env: Settings, sessionmaker: async_sessionmaker[AsyncSession],
                 registry_factory: Callable[[], Registry] | None = None,
                 cosign_factory: Callable[[CosignConfig], CosignVerifier] | None = None,
                 helm_discover: Callable[[list[str]], Awaitable[tuple[list[helm_mod.HelmRelease], list[str]]]] | None = None):
        self.env = env
        self.sm = sessionmaker
        self.registry_factory = registry_factory or self._default_registry
        self.cosign_factory = cosign_factory or (lambda cfg: CosignCli(cfg, env.cosign_bin))
        self.helm_discover = helm_discover or helm_mod.discover

    def _default_registry(self) -> Registry:
        rewrite = self.env.rewrite_map
        insecure = ({self.env.mirror_registry, *rewrite.values()} if self.env.mirror_insecure else set())
        auth_file = self.env.registry_auth_file or (
            os.path.join(os.environ["DOCKER_CONFIG"], "config.json") if os.environ.get("DOCKER_CONFIG") else None)
        return HttpRegistry(insecure_hosts=insecure, rewrite=rewrite, auths=load_docker_auths(auth_file),
                            timeout=self.env.provenance_registry_timeout,
                            max_concurrency=max(1, self.env.provenance_concurrency))

    def _insecure(self, registry: str) -> bool:
        target = self.env.rewrite_map.get(registry, registry)
        return self.env.mirror_insecure and target in {self.env.mirror_registry, *self.env.rewrite_map.values()}

    # ------------------------------------------------------------------ run
    async def run(self, scan_id: int, settings: AppSettings, inv: InventorySnapshot, key_to_id: dict[str, int],
                  log_line: Callable[[str], None] = lambda _m: None, force: bool = False,
                  only: set[int] | None = None) -> dict[int, SupplyChainInputs]:
        ps = settings.provenance
        if not ps.enabled:
            return {}
        started = now()
        async with self.sm() as s:
            images = {i.id: i for i in (await s.execute(
                select(Image).where(Image.id.in_(list(key_to_id.values()) or [0])))).scalars()}
            prev = await self._previous(s, list(images))
        all_items = work_items(inv, key_to_id, images)
        fp = config_fingerprint(ps)
        if only is None:
            items, carried = all_items, []
        else:
            items = [w for w in all_items if w.image_id in only or not self._carryable(prev.get(w.image_id), fp)]
            checking = {w.image_id for w in items}
            carried = [w for w in all_items if w.image_id not in checking]
        cosign_cfg = CosignConfig(ps.cosign_public_key, ps.cosign_certificate_identity_regexp,
                                  ps.cosign_certificate_oidc_issuer_regexp)
        verifier = (self.cosign_factory(cosign_cfg) if (items and ps.verify_signatures and cosign_cfg.enabled)
                    else None)
        reg = self.registry_factory()
        tag_cache: dict[tuple[str, str], asyncio.Future] = {}
        sem = asyncio.Semaphore(max(1, self.env.provenance_concurrency))
        outcomes: list[ImageOutcome] = []

        async def tags_for(registry: str, repo: str) -> list[str] | None:
            key = (registry, repo)
            if key not in tag_cache:
                tag_cache[key] = asyncio.ensure_future(reg.list_tags(registry, repo))
            try:
                return await asyncio.shield(tag_cache[key])
            except (RegistryError, ValueError) as e:
                log.debug("provenance.tags_failed", repo=f"{registry}/{repo}", error=str(e)[:200])
                return None

        async def one(w: ImageWork) -> None:
            async with sem:
                try:
                    outcomes.append(await self._check_image(w, ps, reg, verifier, prev.get(w.image_id), fp, force,
                                                            cosign_cfg.enabled, tags_for))
                except Exception as e:  # noqa: BLE001
                    log.exception("provenance.image_failed", image_id=w.image_id)
                    outcomes.append(ImageOutcome(w.image_id, w.ref.digest, now(), None, None, None, {}, {},
                                                 f"internal error: {e}"[:500], SupplyChainInputs(), None, w.ref.tag))

        try:
            await asyncio.gather(*(one(w) for w in items))
            helm_rows, helm_errors = await self._helm(ps, reg) if ps.helm_releases else ([], [])
        finally:
            closer = getattr(reg, "aclose", None)
            if closer is not None:
                await closer()
        for w in carried:
            outcomes.append(self._carry(w, ps, prev[w.image_id], cosign_cfg.enabled))
        from .. import metrics

        metrics.PROVENANCE_IMAGES.labels("checked").inc(len(items))
        metrics.PROVENANCE_IMAGES.labels("carried").inc(len(carried))
        mutable = {w.image_id: w.mutable for w in all_items}
        await self._persist(scan_id, outcomes, mutable, helm_rows)
        signed = sum(1 for o in outcomes if (o.signature or {}).get("signed"))
        with_sbom = sum(1 for o in outcomes if (o.sbom or {}).get("hasSBOM"))
        with_prov = sum(1 for o in outcomes if (o.provenance or {}).get("hasProvenance"))
        errors = sum(1 for o in outcomes if o.error)
        scope = (f"; {len(items)} checked, {len(carried)} carried from their previous check"
                 if only is not None else "")
        msg = (f"provenance: {len(outcomes)} image(s), {signed} signed, {with_sbom} with SBOM, {with_prov} with "
               f"provenance, {errors} registry error(s); {len(helm_rows)} helm release(s) "
               f"in {int((now() - started).total_seconds())}s{scope}")
        log_line(msg)
        for e in helm_errors[:5]:
            log_line(f"provenance: helm: {e}")
        log.info("provenance.done", scan_id=scan_id, images=len(outcomes), checked=len(items),
                 carried=len(carried), signed=signed, sbom=with_sbom,
                 provenance=with_prov, errors=errors, helm=len(helm_rows))
        return {o.image_id: o.inputs for o in outcomes}

    async def _previous(self, s: AsyncSession, image_ids: list[int]) -> dict[int, ImageProvenance]:
        if not image_ids:
            return {}
        latest = (select(func.max(ImageProvenance.id)).where(ImageProvenance.image_id.in_(image_ids))
                  .group_by(ImageProvenance.image_id))
        rows = (await s.execute(select(ImageProvenance).where(ImageProvenance.id.in_(latest)))).scalars()
        return {r.image_id: r for r in rows}

    @staticmethod
    def _carryable(prev: ImageProvenance | None, fp: str) -> bool:
        """A previous result that may be reused without a registry call (scoped runs)."""
        return prev is not None and not prev.error and (prev.details or {}).get("config") == fp

    def _carry(self, w: ImageWork, ps: ProvenanceSettings, prev: ImageProvenance, cosign_on: bool) -> ImageOutcome:
        details = {k: v for k, v in (prev.details or {}).items() if k not in ("carried", "carriedFromScan")}
        details.update({"carried": True, "carriedFromScan": prev.scan_id})
        updates = dict(prev.updates or {})
        return self._outcome(w, ps, prev.signature, prev.sbom, prev.provenance, updates, details, None,
                             prev.checked_at, cosign_on, prev.digest)

    def _outcome(self, w: ImageWork, ps: ProvenanceSettings, sig, sbom, prov, updates: dict[str, Any],
                 details: dict[str, Any], error: str | None, checked_at: datetime, cosign_on: bool,
                 digest: str | None) -> ImageOutcome:
        ref = w.ref
        primary = ref.tag if ref.tag in updates else (sorted(updates)[0] if updates else ref.tag)
        upd = UpdateInfo.from_json(updates.get(primary or "")) if primary is not None else None
        if error:  # registry unreachable / rate limited: unknown, not failed (no penalty; not cached)
            inputs = build_inputs(None, None, None, upd, ps.model_copy(update={"check_sbom": False,
                                                                                "check_provenance": False}), cosign_on)
        else:
            inputs = build_inputs(sig, sbom, prov, upd, ps, cosign_on)
        score = supply_chain_score(inputs, w.mutable)
        return ImageOutcome(w.image_id, digest, checked_at, sig, sbom, prov, updates, details, error, inputs, score,
                            primary)

    async def _check_image(self, w: ImageWork, ps: ProvenanceSettings, reg: Registry, verifier: CosignVerifier | None,
                           prev: ImageProvenance | None, fp: str, force: bool, cosign_on: bool,
                           tags_for) -> ImageOutcome:
        ref = w.ref
        cutoff = now() - timedelta(hours=ps.recheck_hours)
        reuse = (not force and prev is not None and prev.digest == ref.digest and ref.digest is not None
                 and not prev.error and (prev.details or {}).get("config") == fp
                 and prev.checked_at is not None and prev.checked_at.replace(tzinfo=prev.checked_at.tzinfo or UTC) > cutoff)
        error: str | None = None
        details: dict[str, Any] = {"config": fp}
        if reuse:
            assert prev is not None
            sig, sbom, prov = prev.signature, prev.sbom, prev.provenance
            checked_at = prev.checked_at
            details.update({k: v for k, v in (prev.details or {}).items() if k != "config"})
            details["cached"] = True
        else:
            checked_at = now()
            atts = await collect_attestations(reg, ref, want_att=ps.check_sbom or ps.check_provenance)
            if atts.error:
                error = atts.error
            sig = None
            if ps.verify_signatures:
                existence = signature_existence(atts)
                pull = f"{ref.name}@{atts.digest}" if atts.digest else ref.pullable
                sig_info = await verify_signature(existence, verifier, pull, self._insecure(ref.registry))
                sig = sig_info.as_json()
            sb = sbom_info(atts) if ps.check_sbom else None
            pv = provenance_info(atts) if ps.check_provenance else None
            sbom = sb.as_json() if sb else None
            prov = pv.as_json() if pv else None
            details.update({"referrers": atts.referrers_source, "referrerCount": len(atts.referrers),
                            "indexAttestations": len(atts.index_predicates), "sigTag": atts.sig_tag,
                            "sbomSource": sb.source if sb else None, "provenanceSource": pv.source if pv else None,
                            "resolvedDigest": atts.digest})
        updates: dict[str, Any] = {}
        if ps.check_updates:
            for tag in sorted(w.tags):
                if needs_tag_list(tag):
                    available = await tags_for(ref.registry, ref.repository)
                    if available is None:
                        continue
                    info = compute_update(tag, available, skip_prerelease=ps.skip_prerelease,
                                          update_level=ps.update_level,
                                          max_major_jump=self.env.provenance_max_major_jump)
                else:
                    info = compute_update(tag, None)
                updates[tag] = info.as_json()
        return self._outcome(w, ps, sig, sbom, prov, updates, details, error, checked_at, cosign_on,
                             ref.digest or details.get("resolvedDigest"))

    async def _helm(self, ps: ProvenanceSettings, reg: Registry) -> tuple[list[helm_mod.HelmRelease], list[str]]:
        try:
            releases, errors = await self.helm_discover(list(self.env.excluded_namespaces))
        except Exception as e:  # noqa: BLE001  (403 without the optional RBAC)
            status = getattr(e, "status", None)
            msg = (f"helm release discovery needs secrets list RBAC (provenance.helmReleases.enabled): {status}"
                   if status == 403 else f"helm release discovery failed: {str(e)[:200]}")
            log.warning("provenance.helm_failed", error=msg)
            return [], [msg]
        if ps.check_updates and self.env.provenance_helm_chart_repos:
            await helm_mod.check_chart_updates(
                releases, helm_mod.ChartRepos(list(self.env.provenance_helm_chart_repos)),
                skip_prerelease=ps.skip_prerelease, update_level=ps.update_level, registry=reg,
                max_major_jump=self.env.provenance_max_major_jump)
        return releases, errors

    async def _persist(self, scan_id: int, outcomes: list[ImageOutcome], mutable: dict[int, bool],
                       helm_rows: list[helm_mod.HelmRelease]) -> None:
        async with self.sm() as s, s.begin():
            if outcomes:
                await s.execute(ImageProvenance.__table__.insert(), [{
                    "scan_id": scan_id, "image_id": o.image_id, "digest": o.digest, "checked_at": o.checked_at,
                    "signature": o.signature, "sbom": o.sbom, "provenance": o.provenance, "updates": o.updates,
                    "details": o.details, "error": o.error, "score": o.score} for o in outcomes])
            for o in outcomes:
                await s.execute(update(Image).where(Image.id == o.image_id)
                                .values(provenance=summary_json(o, mutable.get(o.image_id, False))))
            if helm_rows:
                await s.execute(HelmReleaseRow.__table__.insert(), [{
                    "scan_id": scan_id, "namespace": h.namespace, "release_name": h.release_name, "chart": h.chart,
                    "version": h.version, "app_version": h.app_version, "status": h.status, "revision": h.revision,
                    "last_deployed": h.last_deployed, "update": h.update.as_json() if h.update else None,
                    "chart_source": h.chart_source} for h in helm_rows])
            keep = [r for (r,) in (await s.execute(
                select(Scan.id).where(Scan.inventory_complete.is_(True)).order_by(Scan.id.desc()).limit(KEEP_SCANS)
            )).all()] + [scan_id]
            for model in (ImageProvenance, HelmReleaseRow):
                await s.execute(delete(model).where(model.scan_id.notin_(keep)))


def start(stage: ProvenanceStage | None, scan_id: int, settings: AppSettings, inv: InventorySnapshot,
          key_to_id: dict[str, int], log_line: Callable[[str], None], force: bool = False,
          only: set[int] | None = None) -> asyncio.Task | None:
    """Kick off the stage concurrently with scanning (worker hook). `only`: see the module doc."""
    if stage is None or not settings.provenance.enabled:
        return None
    return asyncio.create_task(stage.run(scan_id, settings, inv, key_to_id, log_line, force, only))


async def finish(task: asyncio.Task | None, log_line: Callable[[str], None], cancel: bool = False) -> dict[int, SupplyChainInputs]:
    """Await the stage; failures / cancellation degrade to "no supply-chain data"."""
    if task is None:
        return {}
    if cancel and not task.done():
        task.cancel()
    try:
        return await task
    except asyncio.CancelledError:
        if cancel:
            return {}
        raise
    except Exception as e:  # noqa: BLE001
        log.exception("provenance.stage_failed")
        log_line(f"provenance stage failed: {str(e)[:300]}")
        return {}
