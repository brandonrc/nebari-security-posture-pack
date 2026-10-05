"""Scan accounting and post-scan stage scoping (grace, 2026-10-05; DECISIONS).

Scheduled scans every 6 h with rescanAfterHours=24 rescan only stale images, so `imagesTotal`
(images attempted) is often 0. The scan row now also carries imagesInventoried /
imagesRescanned / imagesSkippedFresh / imagesTargeted, the snapshot always covers the whole
inventory, and the controls engine / auto-reports run only when the scan can have changed
their inputs."""

from __future__ import annotations

import pytest

from posture.worker import ImageSelection, inventory_hash, post_scan_plan, posture_hash
from tests.test_integration import D_ALPINE, container, env, inventory, make_worker  # noqa: F401

D_NEW = "sha256:" + "9" * 64


# ------------------------------------------------------------------ pure helpers
def test_image_selection_counts():
    full = ImageSelection([1, 2], inventoried=80, candidates=80, targeted=None)
    assert full.skipped_fresh == 78
    event = ImageSelection([], inventoried=80, candidates=3, targeted=3)
    assert event.skipped_fresh == 3 and event.targeted == 3


def test_inventory_hash_is_the_image_set():
    assert inventory_hash(["b", "a", "a"]) == inventory_hash(["a", "b"])
    assert inventory_hash(["a"]) != inventory_hash(["a", "b"])


def test_posture_hash_ignores_pods_and_images_but_not_security():
    base = inventory()
    h = posture_hash(base)
    moved = inventory()
    for c in moved.containers:  # restarted pods, new image digest of the same workload
        c.pod = c.pod + "-x"
        c.image_id = (c.image_id or "").replace("2" * 64, "3" * 64) or None
    assert posture_hash(moved) == h
    hardened = inventory()
    hardened.containers[0].security = {"container": {"securityContext": {"runAsNonRoot": True}}, "pod": {}}
    assert posture_hash(hardened) != h
    grown = inventory()
    grown.containers.append(container(workload_name="api", pod="api-1"))
    assert posture_hash(grown) != h


def plan(**kw):
    args = dict(trigger="scheduled", targeted=False, rescanned=0, inventory_hash="i1", posture_hash="p1",
                prev_full_inventory_hash="i1", prev_posture_hash="p1")
    args.update(kw)
    return post_scan_plan(**args)


def test_post_scan_plan_full_scans():
    p = plan()  # nothing rescanned, same images: controls yes, reports no
    assert (p.controls, p.reports) == (True, False) and "unchanged" in p.reports_reason
    assert plan(rescanned=12).reports is True
    assert plan(inventory_hash="i2").reports is True  # an image appeared / went away
    assert plan(prev_full_inventory_hash=None).reports is True  # first scan / pre-0006 rows
    assert plan(trigger="manual", rescanned=1).reports is True


def test_post_scan_plan_targeted_and_event_scans():
    p = plan(trigger="event", targeted=True, rescanned=3)
    assert (p.controls, p.reports) == (False, False)
    assert "unchanged" in p.controls_reason
    p = plan(trigger="event", targeted=True, posture_hash="p2")  # new workload / securityContext
    assert (p.controls, p.reports) == (True, False)
    assert plan(trigger="event", targeted=True, prev_posture_hash=None).controls is True
    assert plan(trigger="manual", targeted=True, rescanned=1).reports is False  # POST /scans {imageIds}


# ------------------------------------------------------------------ worker + Postgres
def worker_with(env, inv_fn=None, controls=False):  # noqa: F811
    w = make_worker(env)
    if inv_fn is not None:
        w.inventory_fn = inv_fn
    if controls:  # record the decision instead of running the real engine
        w.s = w.s.model_copy(update={"controls_engine_enabled": True})
        w.controls_calls = []

        async def run_controls(trigger="scan", scan_id=None, run_id=None):
            w.controls_calls.append(scan_id)
            return None

        w.run_controls = run_controls
    return w


async def auto_reports(env, scan_id):  # noqa: F811
    from sqlalchemy import func, select

    from posture.db.models import Report

    async with env["sm"]() as s:
        return await s.scalar(select(func.count()).select_from(Report).where(
            Report.scan_id == scan_id, Report.created_by == "auto"))


async def run(env, w, body=None, **scan_kw):  # noqa: F811
    c = env["client"]
    if scan_kw:  # event scans are queued by the pod watcher, not the API
        from posture.db.models import Scan

        async with env["sm"]() as s, s.begin():
            row = Scan(status="queued", per_scanner={}, log=[], **scan_kw)
            s.add(row)
            await s.flush()
            sid = row.id
    else:
        r = await c.post("/scans", json=body or {})
        assert r.status_code == 202, r.text
        sid = r.json()["id"]
    assert await w.poll_once() is True
    out = (await c.get(f"/scans/{sid}")).json()
    assert out["status"] == "done", out
    return out


@pytest.mark.integration
async def test_scan_counts_snapshot_and_post_scan_stages(env):  # noqa: F811
    from sqlalchemy import select

    from posture.db.models import ScanSnapshot

    c = env["client"]
    assert (await c.put("/settings", json={"reports": {"autoGenerate": ["inventory", "vuln-export"]}})).status_code == 200

    # 1. first full scan: everything is stale
    w = worker_with(env, controls=True)
    first = await run(env, w)
    assert (first["imagesInventoried"], first["imagesRescanned"], first["imagesSkippedFresh"],
            first["imagesTargeted"], first["imagesTotal"]) == (3, 3, 0, None, 3)
    assert await auto_reports(env, first["id"]) == 2 and w.controls_calls == [first["id"]]

    # 2. scheduled full scan 6 h later: nothing stale. imagesTotal stays "attempted" (0) but the
    #    snapshot and score still cover the whole inventory; no reports, controls still run
    w = worker_with(env, controls=True)
    second = await run(env, w)
    assert (second["imagesInventoried"], second["imagesRescanned"], second["imagesSkippedFresh"],
            second["imagesTotal"]) == (3, 0, 3, 0)
    assert second["score"] == first["score"] and second["progress"] == 1.0
    async with env["sm"]() as s:
        cluster = (await s.execute(select(ScanSnapshot).where(
            ScanSnapshot.scan_id == second["id"], ScanSnapshot.level == "cluster"))).scalar_one()
        workloads = (await s.execute(select(ScanSnapshot).where(
            ScanSnapshot.scan_id == second["id"], ScanSnapshot.level == "workload"))).scalars().all()
    assert cluster.data["containers"] == 5 and cluster.data["workloads"] == 3 and len(workloads) == 3
    assert sum(cluster.data["counts"].values()) > 0  # alpine's findings, although alpine was not rescanned
    assert await auto_reports(env, second["id"]) == 0
    assert any("auto-reports skipped: no image rescanned and inventory unchanged" in x for x in second["log"])
    assert w.controls_calls == [second["id"]]
    assert any("0 image(s) to scan, 3 fresh" in x for x in second["log"])
    listed = next(x for x in (await c.get("/scans")).json() if x["id"] == second["id"])
    assert listed["imagesSkippedFresh"] == 3 and listed["imagesInventoried"] == 3

    # 3. full scan, nothing stale, but an image went away (the CronJob pod was cleaned up): reports
    async def without_job(excluded):
        inv = inventory()
        inv.containers = [x for x in inv.containers if x.workload_kind != "CronJob"]
        return inv

    third = await run(env, worker_with(env, without_job))
    assert (third["imagesInventoried"], third["imagesRescanned"]) == (2, 0)
    assert await auto_reports(env, third["id"]) == 2

    # 4. event scan of `app`, nothing new to scan, same workloads: no reports, controls skipped
    w = worker_with(env, without_job, controls=True)
    ev = await run(env, w, trigger="event", requested_by="pod-watcher", target_namespaces=["app"])
    assert (ev["imagesTargeted"], ev["imagesRescanned"], ev["imagesSkippedFresh"], ev["imagesInventoried"]) == (
        2, 0, 2, 2)
    assert await auto_reports(env, ev["id"]) == 0 and w.controls_calls == []
    assert any("controls engine skipped" in x for x in ev["log"])

    # 5. event scan after a new workload with a new digest appeared: rescans it, runs controls, no reports
    async def with_new_workload(excluded):
        inv = await without_job(excluded)
        inv.containers.append(container(pod="api-1", workload_name="api", image="ghcr.io/org/api:2",
                                        image_id=f"ghcr.io/org/api@{D_NEW}"))
        return inv

    w = worker_with(env, with_new_workload, controls=True)
    ev2 = await run(env, w, trigger="event", requested_by="pod-watcher", target_namespaces=["app"])
    assert (ev2["imagesTargeted"], ev2["imagesRescanned"], ev2["imagesInventoried"]) == (3, 1, 3)
    assert w.controls_calls == [ev2["id"]] and await auto_reports(env, ev2["id"]) == 0
    await c.put("/settings", json={"reports": {"autoGenerate": []}})


@pytest.mark.integration
async def test_scan_metrics_expose_accounting(env):  # noqa: F811
    from prometheus_client import REGISTRY

    from posture import metrics

    async with env["sm"]() as s:
        await metrics.refresh_db_gauges(s)
    assert REGISTRY.get_sample_value("posture_scan_images", {"status": "inventoried"}) == 2
    assert REGISTRY.get_sample_value("posture_scan_images", {"status": "rescanned"}) == 0
    assert REGISTRY.get_sample_value("posture_scan_images", {"status": "skipped_fresh"}) == 2
    assert (REGISTRY.get_sample_value("posture_scan_image_selection_total",
                                      {"trigger": "manual", "result": "skipped_fresh"}) or 0) >= 3
    assert (REGISTRY.get_sample_value("posture_post_scan_stage_total",
                                      {"stage": "reports", "action": "skipped"}) or 0) >= 1
    assert (REGISTRY.get_sample_value("posture_post_scan_stage_total",
                                      {"stage": "controls", "action": "skipped"}) or 0) >= 1
