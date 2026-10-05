"""SCAP stage end to end on Postgres (DESIGN §14): scan worker -> scap-worker hand-off ->
privileged finalize, STIG rows, scoring, API shapes. OpenSCAP itself is faked (the real binary is
exercised by test_oscap.py); everything else (OCI layout flattening, detection, content index,
ARF parsing, persistence, routes) is real.
"""

from __future__ import annotations

import shutil

import pytest

from posture.scap import oscap
from posture.scap.stage import ScapStage
from tests.test_integration import D_ALPINE, D_APP, FakeMirror, FakeScanner, env, inventory  # noqa: F401

from .helpers import BENCHMARKS_YAML, TEST_ARF, TEST_DS, make_layout, os_layer

pytestmark = pytest.mark.integration


class ScapMirror:
    """Mirror.plan + a LocalImageCache stand-in serving prebuilt layouts per digest."""

    def __init__(self, layouts):
        self.layouts = layouts
        self.cache = self
        self.released = []

    def plan(self, ref):
        return ref, False, False

    async def ensure(self, source, digest, insecure, timeout=900):
        if digest not in self.layouts:
            raise RuntimeError(f"manifest unknown: {source}")
        return self.layouts[digest], digest

    def release(self, path):
        self.released.append(path)


@pytest.fixture(scope="module")
def scap_env(env, tmp_path_factory):  # noqa: F811
    base = tmp_path_factory.mktemp("scap")
    content = base / "content" / "local"
    content.mkdir(parents=True)
    shutil.copy(TEST_DS, content / "posture-test-ds.xml")
    extra = base / "benchmarks.yaml"
    extra.write_text(BENCHMARKS_YAML)
    layouts = {
        D_APP: make_layout(base / "img-app", [os_layer(), [("file", "app/server", b"bin", 0o755)]]),
        D_ALPINE: make_layout(base / "img-alpine", [[("dir", "etc"), ("file", "etc/alpine-release", b"3.17.0\n"),
                                                    ("file", "lib/apk/db/installed", b"P:musl\n")]]),
    }
    settings = env["settings"].model_copy(update={
        "scap_content_dir": str(base / "content"), "scap_work_dir": str(base / "work"),
        "scap_content_offline": True, "scap_benchmarks_file": str(extra), "scap_finalize_wait_seconds": 20.0})
    calls = []

    async def fake_eval(rootfs, ds, profile, work, *, timeout, benchmark_id=None, meta=None, **kw):
        calls.append({"rootfs": rootfs, "ds": ds.name, "profile": profile,
                      "osRelease": (rootfs / "etc/os-release").read_text(), "server": (rootfs / "app/server").exists()})
        res = oscap.parse_results(TEST_ARF, meta)
        res.duration_ms = 5
        return res

    return {**env, "settings": settings, "layouts": layouts, "calls": calls, "eval": fake_eval, "base": base}


def worker(se, stages):
    from posture.scanners.clair import parse_clair_json
    from posture.scanners.grype import parse_grype_json
    from posture.scanners.trivy import parse_trivy_json
    from posture.worker import Worker

    async def inv(excluded):
        return inventory()

    scanners = {"trivy": FakeScanner("trivy", parse_trivy_json, "trivy.json"),
                "grype": FakeScanner("grype", parse_grype_json, "grype.json"),
                "clair": FakeScanner("clair", parse_clair_json, "clair.json")}
    w = Worker(se["settings"], se["sm"], scanners=scanners, inventory_fn=inv, mirror=FakeMirror(), stages=stages)
    w._scap_stage = ScapStage(se["settings"], se["sm"], mirror=ScapMirror(se["layouts"]), evaluator=se["eval"],
                              privileged=False)
    return w


async def _ids(c):
    items = (await c.get("/images")).json()["items"]
    return {i["ref"].split("@")[0].split(":")[0].rsplit("/", 1)[-1]: i["id"] for i in items}


async def test_01_split_workers_hand_off_and_results(scap_env):
    se = scap_env
    c = se["client"]
    assert (await c.put("/settings", json={"scanners": {"scap": True}})).json()["scanners"]["scap"] is True
    sid = (await c.post("/scans", json={})).json()["id"]
    scan_w, final_w, scap_w = worker(se, "inventory,scan"), worker(se, "provenance,controls,reports"), worker(se, "scap")
    assert await scan_w.poll_once() is True
    s = (await c.get(f"/scans/{sid}")).json()
    assert s["phase"] == "scanned" and s["scapStatus"] == "queued" and s["scapImages"] == 3
    assert any("queued for the scap-worker" in line for line in s["log"])
    await scap_w.heartbeat()
    assert await scap_w.poll_once() is True  # claims the queued scap job
    s = (await c.get(f"/scans/{sid}")).json()
    assert s["scapStatus"] == "done" and s["scapStats"]["evaluated"] == 1, s
    assert s["scapStats"]["notApplicable"] == 1 and s["scapStats"]["error"] == 1  # busybox has no digest
    assert len(se["calls"]) == 1 and se["calls"][0]["osRelease"].startswith("ID=postureos")
    assert se["calls"][0]["server"] and se["calls"][0]["ds"] == "posture-test-ds.xml"
    assert not any((se["base"] / "work").iterdir())  # rootfs removed after the evaluation
    assert await final_w.poll_once() is True
    s = (await c.get(f"/scans/{sid}")).json()
    assert s["status"] == "done" and s["scapStatus"] == "done"

    ids = await _ids(c)
    web = (await c.get(f"/images/{ids['web']}")).json()
    # 1 CAT III fail of 10 + 4 + 1 evaluated weight
    assert web["stig"]["status"] == "evaluated" and web["stig"]["score"] == 93.3 and web["stig"]["cat3Open"] == 1
    assert web["stig"]["fidelity"] == "degraded"
    st = (await c.get(f"/images/{ids['web']}/stig")).json()
    assert st["status"] == "evaluated" and st["detected"]["os"]["id"] == "postureos"
    b = st["benchmarks"][0]
    assert (b["benchmarkId"], b["xccdfId"], b["source"], b["profileId"], b["version"]) == (
        "test-posture", "xccdf_test.posture_benchmark_minimal", "custom", "xccdf_test.posture_profile_stig", "V1R1")
    assert b["summary"]["pass"] == 2 and b["summary"]["fail"] == 1 and b["summary"]["score"] == 93.3
    assert b["rulesTotal"] == 3 and b["rules"][0]["result"] == "fail"  # fail first
    r0 = b["rules"][0]
    assert (r0["stigId"], r0["ruleVersion"], r0["cci"], r0["severity"]) == ("V-90003", "TEST-01-000030",
                                                                            ["CCI-001384"], "cat3")
    assert set(r0) >= {"ruleId", "stigId", "vulnId", "svId", "cci", "severity", "result", "title", "fixText"}
    one = (await c.get(f"/images/{ids['web']}/stig", params={"severity": "I", "pageSize": 1})).json()
    assert one["benchmarks"][0]["rulesTotal"] == 1 and one["benchmarks"][0]["rules"][0]["severity"] == "cat1"
    q = (await c.get(f"/images/{ids['web']}/stig", params={"result": "pass", "q": "hosts.equiv"})).json()
    assert q["benchmarks"][0]["rulesTotal"] == 1
    alp = (await c.get(f"/images/{ids['alpine']}/stig")).json()
    assert alp["status"] == "notApplicable" and alp["benchmarks"] == [] and "alpine" in alp["reason"]
    assert (await c.get("/images/999999/stig")).status_code == 404

    # /images: sort=stig (nulls last in both orders) and stig=evaluated|na|cat1 filters
    for order in ("asc", "desc"):
        items = (await c.get("/images", params={"sort": "stig", "order": order})).json()["items"]
        assert items[0]["id"] == ids["web"] and all(i["stig"] is None or i["stig"]["score"] is None for i in items[1:])
    names = lambda r: sorted(i["id"] for i in r.json()["items"])  # noqa: E731
    assert names(await c.get("/images", params={"stig": "evaluated"})) == [ids["web"]]
    assert names(await c.get("/images", params={"stig": "na"})) == [ids["alpine"]]
    assert names(await c.get("/images", params={"stig": "cat1"})) == []  # web's only failure is CAT III
    assert names(await c.get("/images", params={"stig": "evaluated,na"})) == sorted([ids["web"], ids["alpine"]])

    bms = (await c.get("/stig/benchmarks")).json()
    assert bms[0]["id"] == "test-posture" and bms[0]["imagesEvaluated"] == 1 and bms[0]["fail"] == 1
    rules = (await c.get("/stig/benchmarks/test-posture/rules")).json()
    assert rules["total"] == 3 and rules["items"][0]["failingImages"] == 1
    assert rules["items"][0]["failing"][0]["imageId"] == ids["web"] and rules["items"][1]["passingImages"] == 1
    assert (await c.get("/stig/benchmarks/test-posture/rules", params={"failing": False})).json()["total"] == 2
    assert (await c.get("/stig/benchmarks/nope/rules")).status_code == 404

    summ = (await c.get("/summary")).json()["stig"]
    assert (summ["evaluated"], summ["fail"], summ["cat3Open"], summ["notApplicable"], summ["errors"]) == (1, 1, 1, 1, 1)
    assert summ["coverage"] == 33.3 and summ["score"] == 93.3
    comp = (await c.get("/compliance/stig")).json()
    assert len(comp["items"]) > 50 and comp["product"]["benchmarks"][0]["id"] == "test-posture"
    scap = next(x for x in (await c.get("/scanners")).json() if x["name"] == "scap")
    assert scap["enabled"] is True and scap["content"][0]["file"] == "posture-test-ds.xml"
    assert scap["dbUpdatedAt"] and scap["lastRunAt"]

    # configuration dimension = mean(workload posture, image STIG scores)
    from posture.scap.scoring import configuration_score

    wl = next(w for w in (await c.get("/workloads")).json() if w["name"] == "web")
    assert wl["postureScore"] is not None
    from posture.posture_checks import evaluate_inventory

    raw = next(p for k, p in evaluate_inventory(inventory()).items() if k[2] == "web").score
    # web's images: web (93.3) and the alpine init container (no STIG score)
    assert wl["postureScore"] == configuration_score(raw, [93.3])


async def test_02_finalize_does_not_wait_without_scap_worker(scap_env):
    from sqlalchemy import delete

    from posture.db.models import WorkerHeartbeat

    se = scap_env
    c = se["client"]
    async with se["sm"]() as s, s.begin():
        await s.execute(delete(WorkerHeartbeat).where(WorkerHeartbeat.id == 3))
    sid = (await c.post("/scans", json={"force": True})).json()["id"]
    assert await worker(se, "inventory,scan").poll_once()
    assert (await c.get(f"/scans/{sid}")).json()["scapStatus"] == "queued"
    assert await worker(se, "provenance,controls,reports").poll_once()
    s = (await c.get(f"/scans/{sid}")).json()
    assert s["status"] == "done" and s["scapStatus"] == "queued"  # scan finished with scap pending
    assert any("scap pending" in line for line in s["log"])
    w = worker(se, "scap")
    assert await w.poll_once() is True
    assert (await c.get(f"/scans/{sid}")).json()["scapStatus"] == "done"


async def test_03_fresh_images_are_not_reevaluated_and_inline_mode(scap_env):
    se = scap_env
    c = se["client"]
    n_calls = len(se["calls"])
    sid = (await c.post("/scans", json={})).json()["id"]  # not forced: every image is fresh
    w = worker(se, "all")  # runs scap inline (all stages)
    assert await w.poll_once() is True
    s = (await c.get(f"/scans/{sid}")).json()
    assert s["status"] == "done" and s["scapStatus"] == "done" and s["scapImages"] == 0
    assert len(se["calls"]) == n_calls
    sid = (await c.post("/scans", json={"force": True})).json()["id"]
    assert await w.poll_once() is True
    s = (await c.get(f"/scans/{sid}")).json()
    assert s["scapStatus"] == "done" and s["scapImages"] == 3 and len(se["calls"]) == n_calls + 1


async def test_04_scap_disabled_is_a_no_op(scap_env):
    se = scap_env
    c = se["client"]
    await c.put("/settings", json={"scanners": {"scap": False}})
    sid = (await c.post("/scans", json={"force": True})).json()["id"]
    assert await worker(se, "inventory,scan").poll_once()
    assert (await c.get(f"/scans/{sid}")).json()["scapStatus"] is None
    assert await worker(se, "provenance,controls,reports").poll_once()
    await c.put("/settings", json={"scanners": {"scap": True}})


async def test_05_reports_from_the_database(scap_env):
    """build_snapshot carries the STIG rows; the bundle, POA&M, SAR and OSCAL AR use them."""
    import io
    import zipfile

    from posture.reports.registry import generate
    from posture.reports.snapshot import build_snapshot

    se = scap_env
    async with se["sm"]() as s:
        snap = await build_snapshot(s, None, None)
    ev = [b for b in snap.stig_results if b.status == "evaluated"]
    assert len(ev) == 1 and ev[0].benchmark_key == "test-posture" and ev[0].release_info.startswith("Release: 1")
    assert {r.result for r in ev[0].rules} == {"pass", "fail"}
    fail = next(r for r in ev[0].rules if r.result == "fail")
    assert fail.first_failed_at is not None  # carried across re-evaluations (SLA clock)
    zf = zipfile.ZipFile(io.BytesIO(generate("stig-checklist", "zip", snap, {}).content))
    assert any(n.startswith("products/") and n.endswith("-test-posture-scan" + str(snap.scan.id) + "-"
                                                        + snap.scan.finished_at.strftime("%Y%m%d") + ".ckl")
               for n in zf.namelist())
    csv = generate("poam", "csv", snap, {}).content.decode()
    assert "SP-STIG-" in csv and "V-90003" in csv
    async with se["sm"]() as s:  # namespace scope without the web image: no STIG rows
        scoped = await build_snapshot(s, None, {"kind": "namespace", "name": "batch"})
    assert all(b.image_id != ev[0].image_id for b in scoped.stig_results)
