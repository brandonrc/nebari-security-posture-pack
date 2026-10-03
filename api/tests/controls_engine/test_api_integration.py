"""End-to-end for DESIGN §13 (Postgres via TEST_DATABASE_URL; schema dropped and recreated):
migration 0003, worker `controls` stage after a scan, on-demand runs queued by the API, every
/compliance engine route, and the oscal-ssp / oscal-component-definition reports."""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest

from tests.test_integration import make_worker

from .fakes import good_world, make_ctx
from .test_ssp import _errors, _validator

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
async def env(tmp_path_factory):
    url = os.environ["TEST_DATABASE_URL"]
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache", "REPORTS_DIR": str(tmp_path_factory.mktemp("rep")),
                       "CONTROLS_ENGINE_ENABLED": "true"})
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
    os.environ["CONTROLS_ENGINE_ENABLED"] = "false"
    os.environ.pop("REPORTS_DIR", None)
    get_settings.cache_clear()
    set_authenticator(None)


def factory(world):
    async def make(cfg, snapshot):
        ctx = make_ctx(world)
        ctx.config.baseline = cfg.baseline
        ctx.snapshot = snapshot
        return ctx

    return make


def worker(env, world=None):
    w = make_worker(env)
    w.controls_context_factory = factory(world or good_world())
    return w


async def test_01_before_any_run(env):
    c = env["client"]
    rows = (await c.get("/compliance/assertions")).json()
    assert len(rows) >= 25 and all(r["status"] is None for r in rows)
    fr = (await c.get("/compliance/families")).json()
    fams = fr["items"]
    assert fr["baseline"] == "moderate" and fr["totals"]["baseline"]["name"] == "moderate"
    keys = {"total", "passing", "partial", "failing", "hybrid", "inherited", "orgProvided",
            "notApplicable", "notAssessed"}
    assert keys <= set(fr["totals"]["baseline"]) and keys == set(fr["totals"]["catalog"])
    assert fr["totals"]["baseline"]["total"] == 287
    assert sum(f["total"] for f in fams) == 287 and keys - {"total"} <= set(fams[0])
    ctl = {x["control"]: x for x in (await c.get("/compliance/controls")).json()}
    assert ctl["AC-7"]["status"] == "not-assessed" and ctl["AC-7"]["baseline"] == "low" and ctl["AC-7"]["family"] == "AC"
    assert ctl["SI-2"]["findingStatus"] == "not_assessed" and ctl["AT-2"]["status"] == "not-assessed"
    assert ctl["AT-2"]["responsibility"] == "org" and fr["totals"]["baseline"]["inherited"] == 0
    cat = (await c.get("/compliance/catalog", params={"family": "AC", "baseline": "moderate"})).json()
    assert cat[0]["control"] == "AC-1" and all(x["family"] == "AC" and "moderate" in x["baselines"] for x in cat)
    assert (await c.get("/compliance/catalog", params={"q": "brute"})).status_code == 200
    assert (await c.get("/compliance/families", params={"baseline": "extreme"})).status_code == 422
    assert (await c.get("/compliance/assertions/nope")).status_code == 404
    assert (await c.get("/compliance/runs")).json() == []


async def test_02_controls_stage_after_scan(env):
    c = env["client"]
    assert (await c.post("/scans", json={})).status_code == 202
    assert await worker(env).poll_once() is True
    runs = (await c.get("/compliance/runs")).json()
    assert len(runs) == 1 and runs[0]["trigger"] == "scan" and runs[0]["status"] == "done"
    assert runs[0]["scanId"] is not None and runs[0]["summary"]["controls"] == 287
    a = {x["id"]: x for x in (await c.get("/compliance/assertions")).json()}
    assert a["kc-brute-force-protection"]["status"] == "pass" and a["kc-brute-force-protection"]["checkedAt"]
    assert a["pack-scan-recent"]["status"] == "pass"  # real scan snapshot from the DB
    assert a["pack-poam-current"]["status"] == "fail"  # open findings, no POA&M generated
    assert a["pack-scanner-db-fresh"]["status"] == "fail"  # fake clair DB is 5 days old
    lp = a["k8s-workload-least-privilege"]  # kube-system privileged pod is exempt; app lacks allowPrivEsc=false
    assert lp["status"] == "fail" and set(lp["evidence"]["failuresByCheck"]) == {"privilege-escalation"}


async def test_03_on_demand_run(env):
    c = env["client"]
    r = await c.post("/compliance/assertions/run")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    assert (await c.post("/compliance/assertions/run")).json()["id"] == r.json()["id"]  # no duplicate
    world = good_world()
    world["keycloak"][""]["failureFactor"] = 50
    assert await worker(env, world).poll_once() is True
    run = (await c.get(f"/compliance/runs/{r.json()['id']}")).json()
    assert run["status"] == "done" and run["trigger"] == "manual" and run["requestedBy"]
    hist = (await c.get("/compliance/assertions/kc-brute-force-protection")).json()
    assert hist["status"] == "fail" and hist["evidence"]["failureFactor"] == 50 and hist["controls"] == ["AC-7"]
    assert [h["status"] for h in hist["history"]] == ["fail", "pass"]
    assert await worker(env).poll_once() is False  # queue empty
    assert (await c.get("/compliance/runs/999")).status_code == 404


async def test_04_controls_and_families(env):
    c = env["client"]
    ctl = {x["control"]: x for x in (await c.get("/compliance/controls")).json()}
    ac7 = ctl["AC-7"]
    assert ac7["status"] == "failing" and ac7["components"] == ["keycloak"]
    assert {o["id"] for o in ac7["objectives"]} == {"ac-7_obj.a", "ac-7_obj.b"}
    assert ac7["assertions"][0]["id"] == "kc-brute-force-protection" and ac7["assertions"][0]["evidence"]
    assert ctl["IA-2(1)"]["status"] == "passing" and ctl["SI-2"]["findingsOpen"] > 0
    assert ctl["AC-2"]["status"] == "partial" and ctl["CM-8"]["status"] == "hybrid"
    assert ctl["RA-5(2)"]["status"] == "failing"  # scan recent, clair DB stale: the single objective fails
    assert ctl["AC-6"]["findingStatus"] == "open" and ctl["AC-6"]["checksFailed"] >= 1
    # M3: the posture failure is an input of the same derivation
    assert ctl["AC-6"]["status"] == "failing" and ctl["AC-6"]["scanEvidence"]["postureFailures"] >= 1
    only = (await c.get("/compliance/controls", params={"status": "passing", "family": "AC"})).json()
    assert only and all(x["status"] == "passing" and x["family"] == "AC" for x in only)
    crm = (await c.get("/compliance/crm")).json()
    assert crm["baseline"] == "moderate" and len(crm["items"]) == 287 and crm["runId"]
    by = {r["control"]: r for r in crm["items"]}
    assert by["AC-7"]["responsibility"] == "provider" and by["AC-2"]["customerResponsibility"]
    fr = (await c.get("/compliance/families")).json()
    fams = {f["family"]: f for f in fr["items"]}
    assert fams["AC"]["failing"] >= 1 and sum(f["total"] for f in fams.values()) == 287
    # totals: baseline = sum of the family rows; catalog = every row /compliance/controls lists
    tb, tc = fr["totals"]["baseline"], fr["totals"]["catalog"]
    from posture.controls_engine.engine import ROLLUP_KEYS

    for k in ROLLUP_KEYS.values():
        assert tb[k] == sum(f[k] for f in fams.values()), k
        assert tc[k] == sum(1 for x in ctl.values() if ROLLUP_KEYS.get(x["status"], "unknown") == k), k
    assert tb["total"] == 287 and tc["total"] == len(ctl) and tc["total"] > tb["total"]
    assert tb["total"] == sum(tb[k] for k in ROLLUP_KEYS.values())
    high = (await c.get("/compliance/families", params={"baseline": "high"})).json()
    assert sum(f["total"] for f in high["items"]) == 370 and high["totals"]["baseline"]["total"] == 370


async def test_05_oscal_reports(env):
    c = env["client"]
    ssp_v = _validator("oscal_ssp_schema.json", "oscal-ssp-schema.json")
    comp_v = _validator("oscal_component_schema.json", "oscal-component-definition-schema.json")
    types = {t["type"] for t in (await c.get("/reports/types")).json()}
    assert {"oscal-ssp", "oscal-component-definition"} <= types
    for rtype, validator in (("oscal-ssp", ssp_v), ("oscal-component-definition", comp_v)):
        r = await c.post("/reports", json={"type": rtype, "format": "json"})
        assert r.status_code == 202, r.text
        from posture.report_worker import ReportWorker  # POST only queues (architecture review M3)

        from posture.config import get_settings

        await ReportWorker(get_settings(), env["sm"], isolation="inline").drain()
        rep = (await c.get(f"/reports/{r.json()['id']}")).json()
        assert rep["status"] == "done", rep
        doc = json.loads((await c.get(f"/reports/{r.json()['id']}/download")).content)
        assert _errors(validator, doc) == []
        if rtype == "oscal-ssp":
            ssp = doc["system-security-plan"]
            props = {p["name"]: p["value"] for p in ssp["system-characteristics"]["props"]}
            runs = (await c.get("/compliance/runs")).json()
            assert props["control-evidence-run"] == str(runs[0]["id"])
            assert ssp["back-matter"]["resources"]


async def test_06_settings_and_disabled(env):
    c = env["client"]
    st = (await c.put("/settings", json={"controlsEngine": {"baseline": "low", "adminSubjects": ["alice"],
                                                            "notApplicable": {"AC-7": "kiosk system"}}})).json()
    assert st["controlsEngine"]["baseline"] == "low" and st["controlsEngine"]["enabled"] is True
    assert sum(f["total"] for f in (await c.get("/compliance/families")).json()["items"]) == 149
    assert (await c.put("/settings", json={"controlsEngine": {"baseline": "nope"}})).status_code == 422
    from posture.config import get_settings

    os.environ["CONTROLS_ENGINE_ENABLED"] = "false"
    get_settings.cache_clear()
    try:
        assert (await c.get("/settings")).json()["controlsEngine"]["enabled"] is False
        assert (await c.post("/compliance/assertions/run")).status_code == 409
    finally:
        os.environ["CONTROLS_ENGINE_ENABLED"] = "true"
        get_settings.cache_clear()
