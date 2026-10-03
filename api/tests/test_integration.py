"""End-to-end: migrations -> worker pipeline (fake k8s/scanners/mirror) -> every API endpoint.

Requires Postgres: TEST_DATABASE_URL=postgresql://user:pass@host:port/db (the schema is
dropped and recreated!). Skipped otherwise.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.integration

FIX = Path(__file__).parent / "fixtures"
D_ALPINE = "sha256:" + "1" * 64
D_APP = "sha256:" + "2" * 64


@pytest.fixture(scope="module")
async def env():
    url = os.environ["TEST_DATABASE_URL"]
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache"})
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
    app = create_app()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1")
    yield {"client": client, "sm": get_sessionmaker(), "settings": get_settings()}
    await client.aclose()
    await dispose_engine()
    set_authenticator(None)


def container(**kw):
    from posture.inventory_model import ContainerRecord

    base = dict(namespace="app", pod="web-1", container="web", container_type="container",
                image="ghcr.io/org/web:1.0", image_id=f"ghcr.io/org/web@{D_APP}", running=True, pod_phase="Running",
                workload_kind="Deployment", workload_name="web", pack="Web App", pod_labels={"app": "web"},
                security={"container": {}, "pod": {}})
    base.update(kw)
    return ContainerRecord(**base)


def inventory():
    from posture.inventory_model import InventorySnapshot, NamespaceInfo, NebariAppInfo, NetworkPolicyInfo

    cs = [
        container(),
        container(pod="web-2"),
        container(container="init", container_type="init", image="alpine:3.17.0",
                  image_id=f"docker.io/library/alpine@{D_ALPINE}"),
        container(namespace="kube-system", pod="dns-1", container="coredns", workload_name="coredns",
                  image="alpine:3.17.0", image_id=f"docker.io/library/alpine@{D_ALPINE}", pack=None,
                  security={"container": {"securityContext": {"privileged": True}}, "pod": {"hostNetwork": True}}),
        container(namespace="batch", pod="job-1", container="job", workload_kind="CronJob", workload_name="nightly",
                  image="busybox", image_id=None, running=False, pod_phase="Succeeded", pack=None),
    ]
    return InventorySnapshot(
        containers=cs,
        namespaces={n: NamespaceInfo(n, {"nebari.dev/managed": "true"} if n == "app" else {})
                    for n in ("app", "kube-system", "batch")},
        network_policies=[NetworkPolicyInfo("app", "deny", {})],
        nebari_apps=[NebariAppInfo("app", "web", "Web App", "web")],
        collected_at=datetime.now(UTC),
    )


class FakeScanner:
    def __init__(self, name, parser, fixture, fail_on=()):
        self.name, self.parser, self.fixture, self.fail_on = name, parser, fixture, set(fail_on)
        self.calls = []

    async def scan(self, ref, *, insecure=False, timeout=600):
        from posture.scanners.base import ScanResult

        self.calls.append(ref)
        if any(f in ref for f in self.fail_on):
            if self.name == "clair":
                raise RuntimeError("adapter exploded")
            return ScanResult(self.name, "error", error="boom")
        if "alpine" not in ref:
            return ScanResult(self.name, "ok", version="1.0", findings=[], raw="{}")
        raw = (FIX / self.fixture).read_text()
        findings, meta = self.parser(json.loads(raw))
        return ScanResult(self.name, "ok", version=meta.get("version") or "1.0", findings=findings, raw=raw,
                          os_family=meta.get("os_family"), os_name=meta.get("os_name"))

    async def version(self):
        return "1.0"

    async def db_updated_at(self):
        return datetime.now(UTC) - (timedelta(days=5) if self.name == "clair" else timedelta(hours=1))


class FakeMirror:
    async def prepare(self, ref, timeout=900):
        from posture.mirror import ScanTarget

        pin = f"@{ref.digest}" if ref.digest else ":latest"
        return ScanTarget(f"mirror:5000/posture-mirror/{ref.repository}{pin}", True, True, ref.pullable,
                          digest_verified=bool(ref.digest))


def make_worker(env, fail_on=()):
    from posture.scanners.clair import parse_clair_json
    from posture.scanners.grype import parse_grype_json
    from posture.scanners.trivy import parse_trivy_json
    from posture.worker import Worker

    async def inv(excluded):
        return inventory()

    scanners = {
        "trivy": FakeScanner("trivy", parse_trivy_json, "trivy.json"),
        "grype": FakeScanner("grype", parse_grype_json, "grype.json"),
        "clair": FakeScanner("clair", parse_clair_json, "clair.json", fail_on=fail_on),
    }
    return Worker(env["settings"], env["sm"], scanners=scanners, inventory_fn=inv, mirror=FakeMirror())


async def test_01_empty_state_shapes(env):
    c = env["client"]
    assert (await c.get("/health")).json() == {"status": "ok"}
    assert (await c.get("/ready")).json() == {"status": "ok"}
    s = (await c.get("/summary")).json()
    assert s["score"] is None and s["grade"] == "?" and s["lastScan"] is None
    assert s["counts"]["critical"] == 0 and s["trend"] == [] and s["topRisks"] == []
    assert s["checks"] == {"passed": 0, "failed": 0, "total": 0}
    assert s["slaOverdue"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert s["exposure"]["kev"] == 0 and s["exposure"]["kevCatalogVersion"]  # S4: KEV exposure count
    assert (await c.get("/images")).json() == {"items": [], "total": 0, "page": 1, "pageSize": 50}
    assert (await c.get("/vulnerabilities")).json()["items"] == []
    assert (await c.get("/workloads")).json() == []
    assert (await c.get("/namespaces")).json() == []
    assert len((await c.get("/checks")).json()) == 16
    assert (await c.get("/checks/privileged")).json()["results"] == []
    assert (await c.get("/checks/nope")).status_code == 404
    assert (await c.get("/scans")).json() == []
    assert len((await c.get("/scanners")).json()) == 3
    assert (await c.get("/export?format=csv")).status_code == 200
    assert (await c.get("/export?format=json")).json()["images"] == []
    ctl0 = {x["control"]: x for x in (await c.get("/compliance/controls")).json()}
    assert ctl0["SI-2"]["findingStatus"] == "not_assessed" and ctl0["SI-2"]["status"] == "not-assessed"
    assert (await c.get("/images/123")).status_code == 404
    assert (await c.get("/me")).json()["isAdmin"] is True
    assert (await c.get("/openapi.json")).status_code == 200


async def test_02_scan_pipeline(env):
    c = env["client"]
    r = await c.post("/scans", json={})
    assert r.status_code == 202
    scan_id = r.json()["id"]
    assert (await c.post("/scans", json={"force": True})).status_code == 409
    w = make_worker(env)
    assert await w.poll_once() is True
    scan = (await c.get(f"/scans/{scan_id}")).json()
    assert scan["status"] == "done", scan
    assert scan["imagesTotal"] == 3 and scan["imagesDone"] == 3 and scan["imagesFailed"] == 0
    assert scan["perScanner"]["trivy"] == {"ok": 3, "error": 0}
    assert any("cluster score" in line for line in scan["log"])

    s = (await c.get("/summary")).json()
    assert s["score"] is not None and s["grade"] in "ABCDF"
    # the scan's 3 unique images (imagesTotal), incl. the busybox job pod that is not running
    assert s["images"] == {"total": 3, "scanned": 3, "failed": 0, "running": 2}
    assert s["workloads"] == 3 and s["namespaces"] == 3
    assert len(s["trend"]) == 1 and s["topRisks"][0]["ref"] == "docker.io/library/alpine:3.17.0"
    assert s["counts"]["critical"] == 1 and s["counts"]["high"] == 2
    assert s["warnings"] == ["clair database is 5 days old"]
    assert s["checks"]["total"] > 0

    imgs = (await c.get("/images", params={"sort": "score"})).json()
    assert imgs["total"] == 3
    alpine = next(i for i in imgs["items"] if "alpine" in i["ref"])
    assert alpine["digest"] == D_ALPINE and alpine["mirrored"] is True and alpine["running"]
    assert alpine["mirrorDigestVerified"] is True and alpine["mirrorRef"].endswith("@" + D_ALPINE)
    assert sorted(alpine["namespaces"]) == ["app", "kube-system"]
    assert alpine["scanners"]["trivy"]["status"] == "ok" and alpine["scanners"]["clair"]["findings"] == 3
    busybox = next(i for i in imgs["items"] if "busybox" in i["ref"])
    assert busybox["running"] is False and busybox["grade"] == "A"
    assert (await c.get("/images", params={"severity": "critical"})).json()["total"] == 1
    assert (await c.get("/images", params={"namespace": "batch"})).json()["total"] == 1
    assert (await c.get("/images", params={"q": "web"})).json()["total"] == 1
    assert (await c.get("/images", params={"pageSize": 1, "page": 2})).json()["items"][0]

    detail = (await c.get(f"/images/{alpine['id']}")).json()
    f = next(x for x in detail["findings"] if x["vulnId"] == "CVE-2024-6119")
    assert f["scanners"] == ["trivy", "grype", "clair"] and f["agreement"] == 1.0 and f["fixable"]
    assert f["perScanner"] == {"trivy": "high", "grype": "high", "clair": "high"}
    assert f["controls"] == ["SI-2"] and f["slaDueAt"]
    only_grype = next(x for x in detail["findings"] if x["vulnId"] == "CVE-2022-48174")
    assert only_grype["scanners"] == ["grype"] and round(only_grype["agreement"], 2) == 0.33
    assert {u["namespace"] for u in detail["usedBy"]} == {"app", "kube-system"}
    assert {s_["scanner"] for s_ in detail["scans"]} == {"trivy", "grype", "clair"}
    assert any(p["checkId"] == "privileged" and p["status"] == "fail" for p in detail["postureFindings"])
    raw = await c.get(f"/images/{alpine['id']}/scans/{detail['scans'][0]['id']}/raw")
    assert raw.status_code == 200 and raw.json()

    vulns = (await c.get("/vulnerabilities")).json()
    assert vulns["total"] == 4 and vulns["items"][0]["severity"] == "critical"
    v = (await c.get("/vulnerabilities/CVE-2024-6119")).json()
    assert v["imagesAffected"] == 1 and v["workloadsAffected"] == 2 and v["images"][0]["package"] == "libcrypto3"
    assert (await c.get("/vulnerabilities", params={"fixable": "false"})).json()["total"] == 1
    assert (await c.get("/vulnerabilities/CVE-0000-0000")).status_code == 404

    wls = (await c.get("/workloads")).json()
    web = next(x for x in wls if x["name"] == "web")
    assert web["pack"] == "Web App" and web["containers"] == 3 and len(web["images"]) == 2 and web["score"] is not None
    dns = next(x for x in wls if x["name"] == "coredns")
    assert dns["systemNamespace"] is True
    assert len((await c.get("/workloads", params={"namespace": "app"})).json()) == 1
    nss = {n["name"]: n for n in (await c.get("/namespaces")).json()}
    assert nss["app"]["managed"] is True and nss["app"]["pack"] == "Web App" and nss["app"]["images"] == 2

    checks = {x["id"]: x for x in (await c.get("/checks")).json()}
    assert checks["privileged"]["failed"] == 1 and checks["privileged"]["controls"] == ["AC-6", "CM-7", "SC-39"]
    priv = (await c.get("/checks/privileged")).json()
    fail = next(r for r in priv["results"] if r["status"] == "fail")
    assert fail["namespace"] == "kube-system" and fail["systemNamespace"] and fail["weight"] == 5.0

    exp = (await c.get("/export", params={"format": "csv"}))
    rows = list(csv.DictReader(io.StringIO(exp.text)))
    assert "attachment" in exp.headers["content-disposition"] and len(rows) == 4
    assert (await c.get("/export")).json()["summary"]["score"] == s["score"]
    ctl = {x["control"]: x for x in (await c.get("/compliance/controls")).json()}
    assert ctl["SI-2"]["findingsOpen"] == 4 and ctl["SI-2(2)"]["findingsOpen"] == 0 and ctl["AC-6"]["findingStatus"] == "open"

    scanners = (await c.get("/scanners")).json()
    assert all(x["version"] for x in scanners) and all(x["lastRunAt"] for x in scanners)

    from posture.reports.snapshot import build_snapshot

    async with env["sm"]() as session:
        snap = await build_snapshot(session, None, {"kind": "namespace", "name": "app"})
    assert snap.scan.id == scan_id and {w_.name for w_ in snap.workloads} == {"web"}
    assert len(snap.findings) == 4 and all(fi.sla_due_at for fi in snap.findings)
    assert snap.summary["counts"]["critical"] == 1
    assert {p.namespace for p in snap.posture_results} == {"app"}


async def test_03_rescan_skips_fresh_and_keeps_first_seen(env):
    c = env["client"]
    alpine = next(i for i in (await c.get("/images")).json()["items"] if "alpine" in i["ref"])
    first = (await c.get(f"/images/{alpine['id']}")).json()["findings"][0]["firstSeenAt"]
    await c.post("/scans", json={})
    await make_worker(env).poll_once()
    scans = (await c.get("/scans")).json()
    assert scans[0]["status"] == "done" and scans[0]["imagesTotal"] == 0
    # targeted + forced rescan; clair adapter raises -> scan still completes
    r = await c.post("/scans", json={"imageIds": [alpine["id"]], "force": True})
    assert r.status_code == 202
    await make_worker(env, fail_on=("alpine",)).poll_once()
    sc = (await c.get(f"/scans/{r.json()['id']}")).json()
    assert sc["status"] == "done" and sc["imagesTotal"] == 1 and sc["perScanner"]["clair"] == {"ok": 0, "error": 1}
    d = (await c.get(f"/images/{alpine['id']}")).json()
    assert d["scanners"]["clair"]["status"] == "error" and "adapter error" in d["scanners"]["clair"]["error"]
    assert d["findings"][0]["firstSeenAt"] == first
    f = next(x for x in d["findings"] if x["vulnId"] == "CVE-2024-6119")
    assert f["scanners"] == ["trivy", "grype"] and f["agreement"] == 1.0
    assert len((await c.get("/summary")).json()["trend"]) == 3
    # the clair error makes alpine stale: a plain (non-forced) scan picks it up again, nothing else
    r = await c.post("/scans", json={})
    await make_worker(env).poll_once()
    sc = (await c.get(f"/scans/{r.json()['id']}")).json()
    assert sc["status"] == "done" and sc["imagesTotal"] == 1
    assert (await c.get(f"/images/{alpine['id']}")).json()["scanners"]["clair"]["status"] == "ok"


async def test_04_cancel_and_settings(env):
    c = env["client"]
    r = await c.post("/scans", json={})
    sid = r.json()["id"]
    assert (await c.delete(f"/scans/{sid}")).json()["status"] == "cancelled"
    assert (await c.delete(f"/scans/{sid}")).status_code == 409
    assert (await c.delete("/scans/99999")).status_code == 404
    st = (await c.put("/settings", json={"parallelism": 5, "remediationSlaDays": {"high": 7},
                                          "adminGroups": ["hacker"], "excludedNamespaces": ["kube-system", " "]})).json()
    assert st["parallelism"] == 5 and st["remediationSlaDays"] == {"critical": 15, "high": 7, "medium": 90, "low": 180}
    assert st["adminGroups"] == ["admin"] and st["excludedNamespaces"] == ["kube-system"]
    assert (await c.get("/settings")).json()["parallelism"] == 5
    assert (await c.put("/settings", json={"parallelism": 0})).status_code == 422
    # backdate firstSeenAt -> SLA overdue shows up on /summary
    from sqlalchemy import update

    from posture.db.models import ConsensusFindingRow

    async with env["sm"]() as s, s.begin():
        await s.execute(update(ConsensusFindingRow).values(first_seen_at=datetime.now(UTC) - timedelta(days=60)))
    assert (await c.get("/summary")).json()["slaOverdue"] == {"critical": 1, "high": 2, "medium": 0, "low": 0}


async def test_05_summary_images_match_latest_scan(env):
    """/summary.images counts the latest done scan's unique images: an image no longer in
    the inventory (stale) is not counted, one with no successful scanner is `failed`."""
    c = env["client"]
    from posture.db.models import Image

    async with env["sm"]() as s, s.begin():
        s.add(Image(key="old/stale@sha256:" + "9" * 64, ref="localhost:32000/old:1", registry_host="localhost:32000",
                    repository="old", tag="1", score=50.0, grade="F", running=False, counts={}, fixable={},
                    scanners={}, warnings=[], tags=[], namespaces=[]))
    before = (await c.get("/summary")).json()["images"]
    assert before == {"total": 3, "scanned": 3, "failed": 0, "running": 2}
    imgs = (await c.get("/images")).json()
    assert imgs["total"] == 4 and next(i for i in imgs["items"] if i["ref"] == "localhost:32000/old:1")["current"] is False
    assert (await c.get("/images", params={"current": "true"})).json()["total"] == 3
    from sqlalchemy import update

    async with env["sm"]() as s, s.begin():  # busybox: every scanner failed, no score
        await s.execute(update(Image).where(Image.ref.like("%busybox%")).values(
            score=None, scanners={"trivy": {"status": "error"}, "grype": {"status": "error"}}))
    assert (await c.get("/summary")).json()["images"] == {"total": 3, "scanned": 2, "failed": 1, "running": 2}


async def test_06_sla_clock_survives_a_rebuilt_digest(env):
    """Compliance review M5: first seen is keyed on (repository, vulnId, package) across digests, so
    rebuilding or retagging an image that still carries the CVE does not restart the SLA clock."""
    from sqlalchemy import select, update

    from posture.analysis import analyze
    from posture.db.models import ConsensusFindingRow, Image
    from posture.mirror import ScanTarget
    from posture.worker import ScanContext

    old = datetime.now(UTC) - timedelta(days=90)
    async with env["sm"]() as s, s.begin():
        src = (await s.execute(select(Image).join(ConsensusFindingRow, ConsensusFindingRow.image_id == Image.id)
                               .limit(1))).scalars().first()
        await s.execute(update(ConsensusFindingRow).where(ConsensusFindingRow.image_id == src.id)
                        .values(first_seen_at=old))
        new = Image(key=f"{src.repository}@sha256:" + "7" * 64, ref=f"{src.registry_host}/{src.repository}:rebuilt",
                    registry_host=src.registry_host, repository=src.repository, tag="rebuilt", running=True,
                    counts={}, fixable={}, scanners={}, warnings=[], tags=[], namespaces=[])
        s.add(new)
        await s.flush()
        new_id, scan_id = new.id, src.last_scan_id
    w = make_worker(env)
    results = [await w.scanners["trivy"].scan("alpine:3.19")]
    assert results[0].findings
    from posture import app_settings

    async with env["sm"]() as s:
        st = await app_settings.load(s)
    ctx = ScanContext(scan_id=scan_id, settings=st, enabled=["trivy"])
    await w._persist_image(ctx, new_id, ScanTarget("mirror/x@sha256:" + "7" * 64, True, True, "src"),
                           results, analyze(results), datetime.now(UTC))
    async with env["sm"]() as s:
        rows = (await s.execute(select(ConsensusFindingRow).where(ConsensusFindingRow.image_id == new_id))
                ).scalars().all()
    carried = [r for r in rows if r.first_seen_at <= old + timedelta(seconds=1)]
    assert rows and carried, "a CVE already seen on another digest of the repository keeps its first-seen date"


async def test_07_summary_kev_exposure(env):
    """S4: KEV findings surface as an exposure count in /summary."""
    from posture.reports import kev

    kev.set_catalog({"version": "fixture", "source": "test", "entries": {
        "CVE-2023-42363": ("2024-01-01", "2024-01-22", 0), "CVE-2024-6119": ("2024-09-01", "2099-01-01", 1)}})
    try:
        ex = (await env["client"].get("/summary")).json()["exposure"]
        assert ex["kev"] >= 2 and ex["kevCves"] == 2 and ex["kevOverdue"] >= 1
        assert ex["kevEarliestDue"] == "2024-01-22" and ex["kevCatalogVersion"] == "fixture"
    finally:
        kev.set_catalog(None)
