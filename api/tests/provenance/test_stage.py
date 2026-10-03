"""Worker stage pieces without a database (_check_image, work items, summary JSON)."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from posture.app_settings import ProvenanceSettings
from posture.config import Settings
from posture.images import ImageRef
from posture.inventory_model import InventorySnapshot
from posture.provenance.stage import (
    ImageWork,
    ProvenanceStage,
    config_fingerprint,
    finish,
    summary_json,
    work_items,
)

from ..conftest import make_container
from .fakes import FakeCosign, FakeRegistry

D = "sha256:" + "d" * 64


def stage():
    return ProvenanceStage(Settings(), None)


async def check(reg, ps, w=None, prev=None, cos=None, force=False):
    async def tags_for(r, repo):
        return reg.tags.get((r, repo))

    w = w or ImageWork(1, ImageRef("ghcr.io", "org/app", "1.0.0", D), {"1.0.0"})
    return await stage()._check_image(w, ps, reg, cos, prev, config_fingerprint(ps), force, cos is not None, tags_for)


async def test_check_image_full():
    reg = FakeRegistry()
    reg.put("ghcr.io", "org/app", D, {"layers": []})
    reg.cosign_sig("ghcr.io", "org/app", D)
    reg.tags[("ghcr.io", "org/app")] = ["1.0.0", "1.0.1", "2.0.0"]
    o = await check(reg, ProvenanceSettings(cosign_public_key="k"), cos=FakeCosign({"ghcr.io/org/app@"}))
    assert o.signature == {"signed": True, "verified": True} and o.sbom == {"hasSBOM": False}
    assert o.updates["1.0.0"]["newestAvailable"] == "2.0.0" and o.inputs.major_behind
    assert o.score == 100 - 20 - 15 - 25 and o.error is None and o.details["sigTag"] is True


async def test_registry_error_is_unknown_not_failed():
    reg = FakeRegistry()
    reg.fail.add("ghcr.io")
    o = await check(reg, ProvenanceSettings())
    assert o.error and o.signature["signed"] is False and "error" in o.signature
    assert o.score is None  # nothing could be checked, no tags either


async def test_disabled_checks_are_absent():
    reg = FakeRegistry()
    reg.put("ghcr.io", "org/app", D, {"layers": []})
    ps = ProvenanceSettings(verify_signatures=False, check_sbom=False, check_provenance=False, check_updates=False)
    o = await check(reg, ps)
    assert (o.signature, o.sbom, o.provenance, o.updates, o.score) == (None, None, None, {}, None)


async def test_cache_reuse_and_invalidation():
    ps = ProvenanceSettings()
    fp = config_fingerprint(ps)
    prev = SimpleNamespace(digest=D, error=None, details={"config": fp, "sigTag": True},
                           checked_at=datetime.now(UTC) - timedelta(hours=1),
                           signature={"signed": True, "verified": False}, sbom={"hasSBOM": True, "format": "spdx"},
                           provenance={"hasProvenance": False})
    reg = FakeRegistry()  # empty: any registry walk would report "not found"
    o = await check(reg, ps, prev=prev)
    assert o.details["cached"] and o.signature == prev.signature and not [c for c in reg.calls if c[0] == "manifest"]
    assert (await check(FakeRegistry(), ps, prev=prev, force=True)).error  # force re-walks
    prev.checked_at = datetime.now(UTC) - timedelta(hours=48)
    assert (await check(FakeRegistry(), ps, prev=prev)).error  # stale
    prev.checked_at = datetime.now(UTC)
    assert (await check(FakeRegistry(), ProvenanceSettings(cosign_public_key="new"), prev=prev)).error  # config changed


def test_work_items_and_summary_json():
    cs = [make_container(image="ghcr.io/org/app:1.0.0"), make_container(pod="p2", image="ghcr.io/org/app:latest")]
    for c in cs:
        c.image_key = "k"
    img = SimpleNamespace(registry_host="ghcr.io", repository="org/app", tag="1.0.0", digest=D)
    [w] = work_items(InventorySnapshot(containers=cs), {"k": 5}, {5: img})
    assert w.image_id == 5 and w.tags == {"1.0.0", "latest"} and w.mutable is True
    o = SimpleNamespace(checked_at=datetime(2026, 1, 1, tzinfo=UTC), signature={"signed": False, "verified": False},
                        sbom={"hasSBOM": False}, provenance=None, updates={"1.0.0": {"currentTag": "1.0.0",
                                                                                     "updateAvailable": False}},
                        primary_tag="1.0.0", score=30.0, error=None,
                        inputs=SimpleNamespace())
    from posture.provenance.scoring import SupplyChainInputs

    o.inputs = SupplyChainInputs(signed=False, verified=False, has_sbom=False)
    j = summary_json(o, True)
    assert j["checkedAt"] == "2026-01-01T00:00:00Z" and j["grade"] == "F" and j["mutableTag"] is True
    assert j["findings"] == ["unsigned", "no-sbom", "mutable-tag"]
    assert j["deductions"][0] == {"reason": "unsigned", "points": 40.0}
    assert "CM-14" in j["controls"] and j["update"]["currentTag"] == "1.0.0"


async def test_finish_degrades_to_empty():
    import asyncio

    async def boom():
        raise RuntimeError("x")

    lines = []
    assert await finish(asyncio.create_task(boom()), lines.append) == {} and "provenance stage failed" in lines[0]
    assert await finish(None, lines.append) == {}

    async def slow():
        await asyncio.sleep(10)

    assert await finish(asyncio.create_task(slow()), lines.append, cancel=True) == {}
