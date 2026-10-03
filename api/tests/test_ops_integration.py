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
