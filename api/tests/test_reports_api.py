"""End-to-end for the compliance report routes (DESIGN §11): /reports*, /compliance/stig,
`stig` on /checks, and the worker's `reports.autoGenerate`. Same harness as
test_integration.py (fake k8s/scanners/mirror, real Postgres via TEST_DATABASE_URL)."""

from __future__ import annotations

import asyncio
import io
import json
import os
import zipfile

import httpx
import pytest

from tests.test_integration import make_worker

pytestmark = pytest.mark.integration


async def drain(env) -> int:
    """POST /reports only queues; the report worker generates (architecture review M3)."""
    from posture.report_worker import ReportWorker

    return await ReportWorker(env["settings"], env["sm"], isolation="inline").drain()


@pytest.fixture(scope="module")
async def env(tmp_path_factory):
    url = os.environ["TEST_DATABASE_URL"]
    reports_dir = tmp_path_factory.mktemp("reports")
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache", "REPORTS_DIR": str(reports_dir),
                       "REPORTS_KEEP_PER_TYPE": "2", "REPORT_WORKER_ISOLATION": "inline"})
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
    yield {"client": client, "sm": get_sessionmaker(), "settings": get_settings(), "dir": reports_dir}
    await client.aclose()
    await dispose_engine()
    for k in ("REPORTS_DIR", "REPORTS_KEEP_PER_TYPE", "REPORT_WORKER_ISOLATION"):
        os.environ.pop(k, None)
    get_settings.cache_clear()
    set_authenticator(None)


async def test_01_before_any_scan(env):
    c = env["client"]
    types = (await c.get("/reports/types")).json()
    assert {t["type"] for t in types} == {"poam", "stig-checklist", "sar", "oscal-ar", "inventory", "vuln-export",
                                         "oscal-ssp", "oscal-component-definition", "crm", "oscal-poam"}
    t = next(x for x in types if x["type"] == "stig-checklist")
    assert t["formats"] == ["ckl", "cklb"] and t["scopes"] == ["cluster", "namespace", "workload"]
    assert t["defaultFormat"] == "cklb" and t["description"]
    assert (await c.get("/reports")).json() == []
    assert (await c.get("/compliance/stig")).json() == []
    r = await c.post("/reports", json={"type": "poam", "format": "xlsx"})
    assert r.status_code == 409 and r.json()["detail"] == "no completed scan yet"


async def test_02_validation(env):
    c = env["client"]
    for body in ({"type": "nope", "format": "csv"}, {"type": "poam", "format": "pdf"},
                 {"type": "poam", "format": "csv", "scope": {"kind": "galaxy"}},
                 {"type": "poam", "format": "csv", "scope": {"kind": "namespace"}},
                 {"type": "poam", "format": "csv", "scope": {"kind": "workload", "name": "app/web"}},
                 {"type": "poam", "format": "csv", "options": {"poamVariant": "x"}}):
        r = await c.post("/reports", json=body)
        assert r.status_code == 422, (body, r.text)
        assert isinstance(r.json()["detail"], str)
    assert (await c.post("/reports", json={"format": "csv"})).status_code == 422
    assert (await c.get("/reports/not-a-uuid")).status_code == 404
    assert (await c.get("/reports/00000000-0000-0000-0000-000000000000")).status_code == 404
    assert (await c.delete("/reports/00000000-0000-0000-0000-000000000000")).status_code == 404


async def test_03_generate_download_delete(env):
    c = env["client"]
    assert (await c.post("/scans", json={})).status_code == 202
    assert await make_worker(env).poll_once() is True
    scan_id = (await c.get("/scans")).json()[0]["id"]

    expect = {
        ("poam", "xlsx"): "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ("poam", "csv"): "text/csv",
        ("stig-checklist", "ckl"): "xml",
        ("stig-checklist", "cklb"): "json",
        ("sar", "html"): "text/html",
        ("oscal-ar", "json"): "json",
        ("inventory", "xlsx"): "spreadsheetml",
        ("vuln-export", "csv"): "text/csv",
        ("vuln-export", "cyclonedx-vex"): "json",
    }
    ids = {}
    for (rtype, fmt), ctype in expect.items():
        r = await c.post("/reports", json={"type": rtype, "format": fmt, "options": {"systemName": "Grace"}})
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "queued" and body["scanId"] == scan_id and body["scope"] == {"kind": "cluster"}
        assert body["createdBy"] and body["createdAt"]
        assert (await c.get(f"/reports/{body['id']}")).json()["status"] == "queued"  # the API never generates
        assert await drain(env) == 1
        rep = (await c.get(f"/reports/{body['id']}")).json()
        assert rep["status"] == "done", rep
        assert rep["sizeBytes"] > 0 and rep["filename"] and rep["error"] is None
        dl = await c.get(f"/reports/{body['id']}/download")
        assert dl.status_code == 200 and ctype in dl.headers["content-type"]
        assert dl.headers["content-disposition"].startswith("attachment;")
        assert rep["filename"] in dl.headers["content-disposition"]
        assert len(dl.content) == rep["sizeBytes"]
        ids[(rtype, fmt)] = (body["id"], dl.content)

    xlsx = ids[("poam", "xlsx")][1]
    assert zipfile.ZipFile(io.BytesIO(xlsx)).namelist()
    cklb = json.loads(ids[("stig-checklist", "cklb")][1])
    assert cklb["stigs"]
    assert ids[("stig-checklist", "ckl")][1].lstrip().startswith(b"<?xml")
    assert json.loads(ids[("oscal-ar", "json")][1])["assessment-results"]["results"]

    # scoped report
    r = await c.post("/reports", json={"type": "inventory", "format": "csv",
                                       "scope": {"kind": "namespace", "name": "app"}})
    await drain(env)
    rep = (await c.get(f"/reports/{r.json()['id']}")).json()
    assert rep["status"] == "done" and rep["scope"] == {"kind": "namespace", "name": "app"}
    body = (await c.get(f"/reports/{rep['id']}/download")).text
    assert "kube-system" not in body and "ghcr.io/org/web" in body
    wl = await c.post("/reports", json={"type": "stig-checklist", "format": "cklb",
                                        "scope": {"kind": "workload", "name": "app/Deployment/web"}})
    await drain(env)
    assert (await c.get(f"/reports/{wl.json()['id']}")).json()["status"] == "done"

    # list filters
    lst = (await c.get("/reports")).json()
    # 11 generated; stig-checklist has 3 and retention (REPORTS_KEEP_PER_TYPE=2) dropped the oldest
    assert len(lst) == len(expect) + 2 - 1 and lst[0]["createdAt"] >= lst[-1]["createdAt"]
    assert ids[("stig-checklist", "ckl")][0] not in {x["id"] for x in lst}
    assert {x["type"] for x in (await c.get("/reports", params={"type": "poam"})).json()} == {"poam"}
    assert len((await c.get("/reports", params={"scanId": scan_id})).json()) == len(lst)
    assert (await c.get("/reports", params={"scanId": 999})).json() == []

    # explicit scan id; unknown scan
    assert (await c.post("/reports", json={"type": "oscal-ar", "format": "json", "scanId": scan_id})).status_code == 202
    assert (await c.post("/reports", json={"type": "oscal-ar", "format": "json", "scanId": 999})).status_code == 404
    await drain(env)

    # delete removes row + file
    rid, _ = ids[("vuln-export", "csv")]
    files_before = set(os.listdir(env["dir"]))
    assert f"{rid}.csv" in files_before
    assert (await c.delete(f"/reports/{rid}")).status_code == 204
    assert (await c.get(f"/reports/{rid}")).status_code == 404
    assert f"{rid}.csv" not in os.listdir(env["dir"])

    # file gone from disk -> 410
    rid, _ = ids[("sar", "html")]
    os.remove(env["dir"] / f"{rid}.html")
    assert (await c.get(f"/reports/{rid}/download")).status_code == 410


async def test_04_retention_keeps_last_n_per_type(env):
    c = env["client"]  # REPORTS_KEEP_PER_TYPE=2
    made = []
    for _ in range(3):
        made.append((await c.post("/reports", json={"type": "poam", "format": "csv"})).json()["id"])
        await drain(env)
    poams = (await c.get("/reports", params={"type": "poam"})).json()
    assert [p["id"] for p in poams] == made[::-1][:2]
    assert not any(f.startswith(made[0]) for f in os.listdir(env["dir"]))
    assert len((await c.get("/reports", params={"type": "inventory"})).json()) == 2  # other types untouched


async def test_05_pdf_dependency_missing_is_503(env, monkeypatch):
    from posture.reports.registry import ReportDependencyMissing
    from posture.routers import reports as reports_router

    def missing():
        raise ReportDependencyMissing("PDF rendering unavailable: no pango")

    monkeypatch.setattr(reports_router, "_pdf_available", missing)
    r = await env["client"].post("/reports", json={"type": "sar", "format": "pdf"})
    assert r.status_code == 503 and "pango" in r.json()["detail"]


async def test_06_generation_failure_marks_row_failed(env, monkeypatch):
    from posture.reports import registry

    def boom(*a, **k):
        raise registry.ReportDependencyMissing("weasyprint libs missing")

    monkeypatch.setattr(registry, "generate", boom)
    r = await env["client"].post("/reports", json={"type": "vuln-export", "format": "json"})
    await drain(env)
    rep = (await env["client"].get(f"/reports/{r.json()['id']}")).json()
    assert rep["status"] == "failed" and rep["error"] == "weasyprint libs missing" and rep["sizeBytes"] is None
    assert (await env["client"].get(f"/reports/{rep['id']}/download")).status_code == 409


async def test_07_compliance_stig_and_check_refs(env):
    c = env["client"]
    rules = (await c.get("/compliance/stig")).json()
    assert len(rules) > 50
    assert {r["cat"] for r in rules} <= {"I", "II", "III"}
    assert {r["status"] for r in rules} <= {"Open", "NotAFinding", "Not_Reviewed"}
    for r in rules:
        assert {"vulnId", "ruleId", "title", "cat", "status", "offenders", "checkId"} <= r.keys()
        assert isinstance(r["offenders"], list)
    # served from posture_results / fixable findings directly; same answer as the full snapshot
    from posture.reports.snapshot import build_snapshot
    from posture.reports.stig import stig_rollup

    async with env["sm"]() as s:
        full = stig_rollup(await build_snapshot(s, None, None), None)
    assert [(r["vulnId"], r["status"], r["offenders"]) for r in full] == \
        [(r["vulnId"], r["status"], r["offenders"]) for r in rules]
    open_priv = [r for r in rules if r["status"] == "Open" and "privileged" in (r.get("checks") or [])]
    # M6: privileged pods in PSA-exempt system namespaces are "verify exemption", not CAT I offenders
    assert open_priv and not any(o.startswith("kube-system/") for r in open_priv for o in r["offenders"])

    checks = {x["id"]: x for x in (await c.get("/checks")).json()}
    stig = checks["privileged"]["stig"]
    assert stig["vulnId"].startswith("V-") and stig["ruleId"].startswith("SV-") and stig["cat"] in ("I", "II", "III")
    assert (await c.get("/checks/privileged")).json()["stig"] == stig


async def test_08_settings_autogenerate_and_worker(env):
    c = env["client"]
    assert (await c.put("/settings", json={"reports": {"autoGenerate": ["bogus"]}})).status_code == 422
    st = (await c.put("/settings", json={"reports": {"autoGenerate": ["poam", "stig-checklist", "oscal-ar",
                                                                       "inventory", "vuln-export"]}})).json()
    assert st["reports"]["autoGenerate"] == ["poam", "stig-checklist", "oscal-ar", "inventory", "vuln-export"]
    before = {r["id"] for r in (await c.get("/reports")).json()}
    r = await c.post("/scans", json={"force": True})
    assert r.status_code == 202
    assert await make_worker(env).poll_once() is True
    sid = r.json()["id"]
    assert (await c.get(f"/scans/{sid}")).json()["status"] == "done"
    await drain(env)  # auto-generated reports go through the same queue
    auto = [x for x in (await c.get("/reports", params={"scanId": sid})).json() if x["id"] not in before]
    assert {(x["type"], x["format"]) for x in auto} == {("poam", "xlsx"), ("stig-checklist", "cklb"),
                                                         ("oscal-ar", "json"), ("inventory", "xlsx"),
                                                         ("vuln-export", "csv")}
    assert all(x["status"] == "done" and x["createdBy"] == "auto" and x["scope"]["kind"] == "cluster" for x in auto)
    assert (await c.get(f"/reports/{auto[0]['id']}/download")).status_code == 200
