"""Worker-side operations / scale features against Postgres (architecture review): size
admission (M2), history retention (M6), images churn (m9), grype DB update vs scan lock (m7),
vuln_rollup and SQL pagination (M4). Same fake k8s/scanners as test_integration.py."""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest

from tests.test_integration import FakeMirror, make_worker

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
async def env(tmp_path_factory):
    url = os.environ["TEST_DATABASE_URL"]
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache",
                       "REPORTS_DIR": str(tmp_path_factory.mktemp("ops-reports"))})
    from posture.config import get_settings

    get_settings.cache_clear()
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(get_settings().database_url)
    async with eng.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await eng.dispose()
    from alembic import command

    from posture.migrate import alembic_config

    await asyncio.to_thread(command.upgrade, alembic_config(), "head")
    from posture.auth import set_authenticator
    from posture.db.session import dispose_engine, get_sessionmaker
    from posture.main import create_app

    set_authenticator(None)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://t/api/v1")
    yield {"client": client, "sm": get_sessionmaker(), "settings": get_settings()}
    await client.aclose()
    await dispose_engine()
    os.environ.pop("REPORTS_DIR", None)
    get_settings.cache_clear()
    set_authenticator(None)


class SizedMirror(FakeMirror):
    """FakeMirror plus the manifest probe used by admission: alpine is 30 GB."""

    def __init__(self):
        self.probes = []

    def plan(self, ref):
        return ref, False, False

    async def _raw_bytes(self, ref, insecure, authfile=False):
        self.probes.append(ref)
        size = 30 * 1024**3 if "alpine" in ref else 1000
        return json.dumps({"config": {"size": 1}, "layers": [{"size": size}]}).encode()


async def test_admission_defers_big_images(env):
    c = env["client"]
    assert (await c.post("/scans", json={})).status_code == 202
    w = make_worker(env)
    w.mirror = SizedMirror()
    assert await w.poll_once() is True
    scan = (await c.get("/scans")).json()[0]
    assert scan["status"] == "done" and scan["imagesDone"] == 3
    detail = (await c.get(f"/scans/{scan['id']}")).json()
    assert any("exceeds SCAN_MAX_IMAGE_GB" in line for line in detail["log"])
    assert any("scanned last, one at a time" in line for line in detail["log"])
    calls = w.scanners["trivy"].calls
    assert len(calls) == 3 and "alpine" in calls[-1]  # big image scanned after everything else
    from sqlalchemy import select

    from posture.db.models import Image

    async with env["sm"]() as s:
        sizes = {i.ref: i.size_bytes for i in (await s.execute(select(Image))).scalars()}
    assert sizes["docker.io/library/alpine:3.17.0"] == 30 * 1024**3 + 1
    # sizes are probed once per digest
    probes = len(w.mirror.probes)
    r = await c.post("/scans", json={"force": True})
    w2 = make_worker(env)
    w2.mirror = w.mirror
    await w2.poll_once()
    assert len(w.mirror.probes) == probes and (await c.get(f"/scans/{r.json()['id']}")).json()["status"] == "done"


async def test_vuln_rollup_matches_python_grouping(env):
    from posture.db.session import get_sessionmaker
    from posture.routers.vulnerabilities import _rows, _workloads_by_image, group_by_vuln

    c = env["client"]
    async with get_sessionmaker()() as s:
        legacy = group_by_vuln(await _rows(s), await _workloads_by_image(s))
    got = (await c.get("/vulnerabilities", params={"pageSize": 500})).json()
    assert got["total"] == len(legacy) == len(got["items"]) > 0
    for item in got["items"]:
        old = legacy[item["vulnId"]]
        for k in ("severity", "scanners", "agreement", "imagesAffected", "workloadsAffected", "fixAvailable",
                  "cvss", "packages", "controls"):
            assert item[k] == old[k], (item["vulnId"], k)
        assert item["kev"] is False and "firstSeenAt" in item
    # every sort, keyset walk == offset pages
    for sort in ("severity", "imagesAffected", "workloadsAffected", "cvss", "agreement", "firstSeen", "vulnId"):
        for order in ("desc", "asc"):
            full = [i["vulnId"] for i in (await c.get("/vulnerabilities", params={
                "sort": sort, "order": order, "pageSize": 500})).json()["items"]]
            walked, cursor = [], None
            while True:
                params = {"sort": sort, "order": order, "pageSize": 1}
                if cursor:
                    params["cursor"] = cursor
                body = (await c.get("/vulnerabilities", params=params)).json()
                walked += [i["vulnId"] for i in body["items"]]
                cursor = body["nextCursor"]
                if not cursor:
                    break
            assert walked == full, (sort, order)
            paged = [(await c.get("/vulnerabilities", params={"sort": sort, "order": order, "pageSize": 1,
                                                              "page": p})).json()["items"][0]["vulnId"]
                     for p in range(1, len(full) + 1)]
            assert paged == full
    assert (await c.get("/vulnerabilities", params={"cursor": "garbage!"})).status_code == 400
    sev = (await c.get("/vulnerabilities", params={"sort": "severity"})).json()["items"]
    assert sev[0]["severity"] == "critical"
    # q over vulnId / title / packages (pg_trgm), with LIKE wildcards escaped
    assert {i["vulnId"] for i in (await c.get("/vulnerabilities", params={"q": "libcrypto"})).json()["items"]} \
        == {v for v, g in legacy.items() if any("libcrypto" in p for p in g["packages"])}
    assert (await c.get("/vulnerabilities", params={"q": "%"})).json()["total"] == 0
    assert (await c.get("/vulnerabilities", params={"severity": "critical,high"})).json()["total"] == \
        sum(1 for g in legacy.values() if g["severity"] in ("critical", "high"))


async def test_image_findings_paginated_in_sql(env):
    c = env["client"]
    alpine = next(i for i in (await c.get("/images")).json()["items"] if "alpine" in i["ref"])
    full = (await c.get(f"/images/{alpine['id']}")).json()  # no page: first 500, back-compat
    assert full["truncated"] is False and full["findingsTotal"] == len(full["findings"]) > 2
    summ = full["findingsSummary"]
    assert summ["total"] == summ["filtered"] == len(full["findings"])
    assert summ["flaggedByAll"] == sum(1 for f in full["findings"] if len(f["scanners"]) == summ["scannersOk"])
    assert sum(summ["bySeverity"].values()) == summ["total"] and summ["fixable"] == sum(f["fixable"] for f in full["findings"])
    ranks = ["critical", "high", "medium", "low", "negligible", "unknown"]
    assert [ranks.index(f["severity"]) for f in full["findings"]] == sorted(ranks.index(f["severity"]) for f in full["findings"])
    p1 = (await c.get(f"/images/{alpine['id']}", params={"page": 1, "pageSize": 2})).json()
    p2 = (await c.get(f"/images/{alpine['id']}", params={"page": 2, "pageSize": 2})).json()
    assert [f["vulnId"] for f in p1["findings"] + p2["findings"]] == [f["vulnId"] for f in full["findings"]][:4]
    assert p1["truncated"] is False and p1["findingsPageSize"] == 2
    fx = (await c.get(f"/images/{alpine['id']}", params={"page": 1, "fixable": "true"})).json()
    assert fx["findingsTotal"] == summ["fixable"] and all(f["fixable"] for f in fx["findings"])
    q = (await c.get(f"/images/{alpine['id']}", params={"page": 1, "q": "BUSYBOX"})).json()
    assert q["findingsTotal"] >= 1 and all("busybox" in f["package"] for f in q["findings"])
    assert q["findingsSummary"]["total"] == summ["total"]
    by_pkg = (await c.get(f"/images/{alpine['id']}", params={"page": 1, "sort": "package", "order": "asc"})).json()
    assert [f["package"] for f in by_pkg["findings"]] == sorted(f["package"] for f in by_pkg["findings"])
    dis = (await c.get(f"/images/{alpine['id']}", params={"page": 1, "disagree": "true"})).json()
    assert dis["findingsTotal"] == summ["total"] - summ["flaggedByAll"]


async def test_summary_from_snapshot(env):
    from posture.db.models import Image
    from sqlalchemy import select

    s1 = (await env["client"].get("/summary")).json()
    async with env["sm"]() as s:
        imgs = [i for i in (await s.execute(select(Image).where(Image.running.is_(True)))).scalars()
                if i.score is not None]
    assert s1["counts"]["critical"] == sum(int((i.counts or {}).get("critical", 0)) for i in imgs)
    assert s1["fixable"]["high"] == sum(int((i.fixable or {}).get("high", 0)) for i in imgs)
    assert s1["topRisks"][0]["ref"] == min(imgs, key=lambda i: i.score).ref


async def _xmins(env):
    from sqlalchemy import text

    async with env["sm"]() as s:
        return dict((await s.execute(text("SELECT key, xmin::text FROM images"))).all())


async def test_images_rows_untouched_when_unchanged(env):
    from posture.db.models import Image

    async with env["sm"]() as s, s.begin():  # an image no pod runs any more
        s.add(Image(key="old/stale@sha256:" + "9" * 64, ref="old/stale", registry_host="r", repository="old",
                    running=False, counts={}, fixable={}, scanners={}, warnings=[], tags=[], namespaces=[]))
    before = await _xmins(env)
    r = await env["client"].post("/scans", json={})
    assert r.status_code == 202
    w = make_worker(env)
    w.provenance_stage = None  # the provenance stage rewrites images.provenance (its own data) per scan
    await w.poll_once()
    assert (await env["client"].get(f"/scans/{r.json()['id']}")).json()["imagesTotal"] == 0  # all fresh
    after = await _xmins(env)
    assert after == before  # m9: no UPDATE on unchanged rows (was: running=false on the whole table)


async def test_history_retention_keeps_referenced_rows(env):
    from sqlalchemy import func, select

    from posture.db.models import FindingRow, ImageScan, Scan, ScanSnapshot, VulnRollupRow

    for _ in range(2):
        await env["client"].post("/scans", json={"force": True})
        await make_worker(env).poll_once()
    async with env["sm"]() as s:
        n_scans = await s.scalar(select(func.count()).select_from(Scan))
        referenced = {i for (i,) in (await s.execute(select(FindingRow.image_scan_id).distinct())).all()}
    assert n_scans >= 4
    w = make_worker(env)
    out = await w.prune_history(retain=1)
    assert out["image_scans"] > 0 and out["scan_snapshots"] > 0
    async with env["sm"]() as s:
        latest = await s.scalar(select(func.max(Scan.id)).where(Scan.status == "done"))
        left = {i for (i,) in (await s.execute(select(ImageScan.id))).all()}
        snap_scans = {i for (i,) in (await s.execute(select(ScanSnapshot.scan_id).distinct())).all()}
        rollups = {i for (i,) in (await s.execute(select(VulnRollupRow.scan_id).distinct())).all()}
    assert referenced <= left  # current findings keep their image_scans rows
    assert snap_scans == {latest} and latest in rollups and len(rollups) <= 2
    assert (await env["client"].get("/summary")).json()["score"] is not None
    assert (await env["client"].get("/vulnerabilities")).json()["total"] > 0


async def test_grype_db_update_never_overlaps_a_scan(env):
    from posture.scanners.grype import GrypeScanner

    class FakeGrype(GrypeScanner):
        def __init__(self):
            super().__init__("grype", "/tmp/posture-test-cache")
            self.updates = 0

        async def update_db(self, timeout=1800):
            self.updates += 1
            return True, None

        async def version(self):
            return "1"

        async def db_updated_at(self):
            return None

    w = make_worker(env)
    g = FakeGrype()
    w.scanners = {"grype": g}
    async with w.scanning():
        assert await w.update_grype_db() is False and w._grype_update_pending  # deferred
        assert g.updates == 0
    await asyncio.sleep(0.2)  # the deferred update runs once the scan window closes
    assert g.updates == 1 and not w._grype_update_pending
    # a scan that starts during an update waits for it
    order = []

    async def slow_update(timeout=1800):
        order.append("update-start")
        await asyncio.sleep(0.2)
        order.append("update-end")
        return True, None

    g.update_db = slow_update
    upd = asyncio.create_task(w.update_grype_db())
    await asyncio.sleep(0.05)
    async with w.scanning():
        order.append("scan")
    await upd
    assert order == ["update-start", "update-end", "scan"]


async def test_compat_report_materialized_once_per_scan(env):
    from sqlalchemy import select

    from posture import app_settings
    from posture.db.models import CompatReportRow, Scan
    from posture.provenance.report import go_json, load_report

    async with env["sm"]() as s:
        rows = (await s.execute(select(CompatReportRow).order_by(CompatReportRow.scan_id.desc()))).scalars().all()
        assert rows, "the worker stores one compat report per completed scan with provenance results"
        latest = rows[0]
        scan = await s.get(Scan, latest.scan_id)
        name = (await app_settings.load(s)).system_name
        fresh = go_json(await load_report(s, scan, name), indent=True)
    assert latest.body == fresh  # stored bytes == what the router used to render per request
    r = await env["client"].get("http://t/api/reports/latest")
    assert r.status_code == 200 and r.content == latest.body
    lst = (await env["client"].get("http://t/api/reports")).json()
    assert lst[0]["filename"] == latest.filename and lst[0]["summary"] == latest.summary
    async with env["sm"]() as s, s.begin():  # served from the table: tamper with it and see it
        row = await s.get(CompatReportRow, latest.scan_id)
        row.body = latest.body.replace(b'"metadata"', b'"metadata" ', 1)
    from posture.routers.provenance_compat import CACHE

    CACHE.latest_key = None
    assert (await env["client"].get(f"http://t/api/reports/{latest.filename}")).content.startswith(b"{") and \
        b'"metadata" ' in (await env["client"].get(f"http://t/api/reports/{latest.filename}")).content


async def test_pod_watcher_queues_one_targeted_scan(env):
    import threading

    from sqlalchemy import select

    from posture.db.models import Scan
    from posture.event_scans import PodWatcher, enqueue_event_scan

    d_new = "sha256:" + "7" * 64
    d_new2 = "sha256:" + "8" * 64
    known = "ghcr.io/org/web@sha256:" + "2" * 64  # scanned by the earlier tests

    def ev(ns, ref, digest):
        return {"type": "ADDED", "object": {"metadata": {"namespace": ns}, "status": {"containerStatuses": [
            {"image": f"{ref}:1", "imageID": f"{ref}@{digest}"}]}}}

    events = [ev("app", "ghcr.io/org/web", "sha256:" + "2" * 64),
              ev("team-a", "ghcr.io/org/new", d_new), ev("team-b", "ghcr.io/org/new2", d_new2),
              ev("team-a", "ghcr.io/org/new", d_new)]

    def stream(stop: threading.Event):
        yield from events
        stop.wait(5)

    w = PodWatcher(env["sm"], stream_factory=stream, debounce=1.0, quiet=0.3)
    task = asyncio.create_task(w.run())
    for _ in range(50):
        await asyncio.sleep(0.1)
        if w.queued:
            break
    w.stop()
    task.cancel()
    assert len(w.queued) == 1
    async with env["sm"]() as s:
        scan = await s.get(Scan, w.queued[0])
    assert scan.trigger == "event" and scan.status == "queued" and scan.target_namespaces == ["team-a", "team-b"]
    assert known in w.known
    # a second burst merges into the queued event scan; a queued full scan absorbs it
    assert await enqueue_event_scan(env["sm"], ["team-c"]) == scan.id
    async with env["sm"]() as s:
        assert (await s.get(Scan, scan.id)).target_namespaces == ["team-a", "team-b", "team-c"]
    # the event scan runs like a namespace-targeted scan and does not reset the schedule
    worker = make_worker(env)
    before_due = await worker.next_scan_due()
    assert await worker.poll_once() is True
    async with env["sm"]() as s:
        done = await s.get(Scan, scan.id)
        assert done.status == "done"
    assert await worker.next_scan_due() == before_due
    async with env["sm"]() as s, s.begin():
        s.add(Scan(trigger="manual", status="queued", per_scanner={}, log=[]))
    assert await enqueue_event_scan(env["sm"], ["team-d"]) is None
    async with env["sm"]() as s, s.begin():
        for sc in (await s.execute(select(Scan).where(Scan.status == "queued"))).scalars():
            sc.status = "cancelled"


async def test_metrics_ignore_targeted_scans(env):
    """Scan gauges come from the latest done *full* scan: a later event scan of one namespace
    must neither shrink posture_scan_images nor refresh the last-success timestamp."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from posture import metrics
    from posture.db.models import Scan

    async with env["sm"]() as s:
        full = (await s.execute(select(Scan).where(
            Scan.status == "done", Scan.target_image_ids.is_(None), Scan.target_namespaces.is_(None))
            .order_by(Scan.id.desc()).limit(1))).scalar_one()
        full_total, full_finished = full.images_total, full.finished_at.timestamp()
        later = datetime.now(UTC) + timedelta(hours=1)
        s.add(Scan(trigger="event", status="done", requested_by="pod-watcher", target_namespaces=["kube-system"],
                   images_total=1, images_done=1, images_failed=0, started_at=later, finished_at=later))
        await s.commit()
        await metrics._refresh(s)
    assert metrics.SCAN_IMAGES.labels("total")._value.get() == full_total
    assert metrics.LAST_SUCCESS._value.get() == full_finished
