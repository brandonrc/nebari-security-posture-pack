"""Report worker (architecture review M3): queue claims with SKIP LOCKED + lease, heartbeat,
expired-lease requeue, attempt cap, per-report timeout (inline and child process), and
retention by count and bytes. Real Postgres via TEST_DATABASE_URL."""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests.test_integration import make_worker

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
async def env(tmp_path_factory):
    url = os.environ["TEST_DATABASE_URL"]
    reports_dir = tmp_path_factory.mktemp("rw-reports")
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache", "REPORTS_DIR": str(reports_dir)})
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
    e = {"client": client, "sm": get_sessionmaker(), "settings": get_settings(), "dir": reports_dir}
    assert (await client.post("/scans", json={})).status_code == 202
    assert await make_worker(e).poll_once() is True
    yield e
    await client.aclose()
    await dispose_engine()
    os.environ.pop("REPORTS_DIR", None)
    get_settings.cache_clear()
    set_authenticator(None)


def rw(env, **kw):
    from posture.report_worker import ReportWorker

    kw.setdefault("isolation", "inline")
    return ReportWorker(env["settings"], env["sm"], **kw)


async def _clear(env):
    from sqlalchemy import delete

    from posture.db.models import Report

    async with env["sm"]() as s, s.begin():
        await s.execute(delete(Report))


async def _post(env, rtype="vuln-export", fmt="csv") -> str:
    r = await env["client"].post("/reports", json={"type": rtype, "format": fmt})
    assert r.status_code == 202, r.text
    return r.json()["id"]


async def _get(env, rid):
    return (await env["client"].get(f"/reports/{rid}")).json()


async def test_api_only_queues_and_worker_claims_once(env):
    await _clear(env)
    ids = [await _post(env) for _ in range(3)]
    await asyncio.sleep(0.05)
    assert {(await _get(env, i))["status"] for i in ids} == {"queued"}
    a, b = rw(env, worker_id="a"), rw(env, worker_id="b")
    claimed = await asyncio.gather(a.claim(), b.claim(), a.claim())
    assert len({str(c) for c in claimed}) == 3 and None not in claimed  # SKIP LOCKED: no double claims
    assert await b.claim() is None
    from posture.db.models import Report

    async with env["sm"]() as s:
        rows = [await s.get(Report, c) for c in claimed]
    assert all(r.status == "running" and r.attempts == 1 and r.leased_until > datetime.now(UTC) for r in rows)
    assert {r.worker_id for r in rows} == {"a", "b"}
    for c, r in zip(claimed, rows, strict=True):  # generate as the owner
        owner = a if r.worker_id == "a" else b
        assert await owner.process(c) == "done"
    rep = await _get(env, ids[0])
    assert rep["status"] == "done" and rep["startedAt"] and rep["finishedAt"] and rep["attempts"] == 1


async def test_heartbeat_extends_lease_only_for_owner(env):
    await _clear(env)
    await _post(env)
    w = rw(env, worker_id="owner")
    rid = await w.claim()
    from posture.db.models import Report

    async with env["sm"]() as s:
        before = (await s.get(Report, rid)).leased_until
    await asyncio.sleep(0.01)
    assert await w.heartbeat(rid) is True
    assert await rw(env, worker_id="intruder").heartbeat(rid) is False
    async with env["sm"]() as s:
        assert (await s.get(Report, rid)).leased_until > before
    assert await w.process(rid) == "done"


async def test_expired_lease_requeued_then_failed_after_max_attempts(env):
    from sqlalchemy import update

    from posture.db.models import Report

    await _clear(env)
    rid = await _post(env)
    dead = rw(env, worker_id="dead")
    for attempt in (1, 2):
        assert str(await dead.claim()) == rid
        async with env["sm"]() as s, s.begin():  # the worker died: its lease runs out
            await s.execute(update(Report).where(Report.id == uuid.UUID(rid))
                            .values(leased_until=datetime.now(UTC) - timedelta(seconds=1)))
        assert await rw(env, worker_id="other").requeue_expired() == 1
        rep = await _get(env, rid)
        if attempt == 1:
            assert rep["status"] == "queued" and rep["attempts"] == 1
        else:  # REPORT_MAX_ATTEMPTS=2: a report that keeps killing its worker is failed, not retried forever
            assert rep["status"] == "failed" and "lease expired" in rep["error"] and rep["finishedAt"]
    # a late finish from the dead worker cannot overwrite the row
    from posture import report_jobs

    assert await report_jobs.generate(env["sm"], rid, "dead") == "failed"


async def test_legacy_running_row_without_lease_is_recovered(env):
    from posture.db.models import Report

    await _clear(env)
    async with env["sm"]() as s, s.begin():  # left `running` by the old in-API BackgroundTask
        s.add(Report(id=uuid.uuid4(), type="poam", format="csv", scope_kind="cluster", status="running",
                     created_at=datetime.now(UTC) - timedelta(hours=1), options={}))
    assert await rw(env).requeue_expired() == 1
    assert await rw(env).drain() == 1
    rows = (await env["client"].get("/reports")).json()
    assert [r["status"] for r in rows] == ["done"]


async def test_inline_timeout_marks_failed(env, monkeypatch):
    from posture.reports import registry

    def slow(*a, **k):
        time.sleep(1.5)
        raise AssertionError("should have been abandoned")

    monkeypatch.setattr(registry, "generate", slow)
    await _clear(env)
    rid = await _post(env)
    w = rw(env)
    w.timeout = 0.3
    assert await w.drain() == 1
    rep = await _get(env, rid)
    assert rep["status"] == "failed" and "timed out" in rep["error"]
    await asyncio.sleep(1.5)  # let the abandoned thread finish before the next test


async def test_child_process_generates_and_times_out(env):
    await _clear(env)
    rid = await _post(env, "inventory", "csv")
    w = rw(env, isolation="process")
    assert await w.drain() == 1
    rep = await _get(env, rid)
    assert rep["status"] == "done", rep
    dl = await env["client"].get(f"/reports/{rid}/download")
    assert dl.status_code == 200 and "ghcr.io/org/web" in dl.text
    rid2 = await _post(env, "inventory", "csv")
    w.timeout = 0.05  # the child cannot even import in time: killed, row failed
    assert await w.drain() == 1
    rep2 = await _get(env, rid2)
    assert rep2["status"] == "failed" and "timed out" in rep2["error"]


async def test_retention_by_count_and_bytes(env):
    from posture import report_jobs

    await _clear(env)
    ids = []
    for _ in range(4):
        ids.append(await _post(env, "vuln-export", "csv"))
        await rw(env).drain()
        await asyncio.sleep(0.01)
    ids.append(await _post(env, "inventory", "csv"))
    await rw(env).drain()
    rows = {r["id"]: r for r in (await env["client"].get("/reports")).json()}
    assert len(rows) == 5  # REPORTS_RETENTION_PER_TYPE default 20
    assert await report_jobs.prune(env["sm"], keep=2, max_total_bytes=0) == 2
    left = (await env["client"].get("/reports")).json()
    assert {r["id"] for r in left} == {ids[2], ids[3], ids[4]}
    assert not any(f.startswith(ids[0]) for f in os.listdir(env["dir"]))
    newest = left[0]
    # byte cap: only the newest report fits; the newest always stays even when it alone is over the cap
    assert await report_jobs.prune(env["sm"], keep=20, max_total_bytes=newest["sizeBytes"]) == 2
    assert [r["id"] for r in (await env["client"].get("/reports")).json()] == [newest["id"]]
    assert await report_jobs.prune(env["sm"], keep=20, max_total_bytes=1) == 0


async def test_worker_auto_generate_only_queues(env):
    from posture import report_jobs

    await _clear(env)
    ids = await report_jobs.enqueue_auto(env["sm"], (await env["client"].get("/scans")).json()[0]["id"],
                                         ["poam", "bogus", "inventory"])
    assert len(ids) == 2
    assert {(await _get(env, i))["status"] for i in ids} == {"queued"}
    assert await rw(env).drain() == 2
    assert {(await _get(env, i))["status"] for i in ids} == {"done"}
