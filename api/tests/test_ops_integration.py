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
