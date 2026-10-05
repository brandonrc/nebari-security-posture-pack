"""End-to-end VEX: worker (MIRROR_MODE=local, scanners see an oci-dir: path) -> statements
matched by the image's source ref -> suppressed findings in /images, /summary, /export, the
rollup, control coverage and the report snapshot (CycloneDX VEX, POA&M).

Requires Postgres (TEST_DATABASE_URL; the schema is dropped and recreated). Skipped otherwise.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os

import httpx
import pytest

from tests.test_integration import D_ALPINE, make_worker

pytestmark = pytest.mark.integration

VEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://example.org/vex/site-2026-10",
    "author": "ISSO, Example Org",
    "timestamp": "2026-10-05T00:00:00Z",
    "version": 1,
    "statements": [
        {"vulnerability": {"name": "CVE-2024-6119"},
         "products": [{"@id": "pkg:oci/alpine?repository_url=docker.io/library/alpine",
                       "subcomponents": [{"@id": "pkg:apk/alpine/libcrypto3"}]}],
         "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
         "impact_statement": "X.509 name checks are never reached: the init container makes no TLS connections."},
        {"vulnerability": {"name": "CVE-2023-42363"},
         "products": [f"pkg:oci/alpine@{D_ALPINE.replace(':', '%3A')}"],
         "status": "under_investigation", "status_notes": "busybox awk; reachability being checked"},
        {"vulnerability": {"name": "CVE-2024-6119"},  # another image's product: must not apply here
         "products": ["ghcr.io/org/web"], "status": "not_affected", "justification": "component_not_present"},
    ],
}


class LocalMirror:
    """MIRROR_MODE=local as the worker sees it: the scanners get a per-digest OCI layout path,
    never the image name, so only the source ref / digests can match VEX products."""

    async def prepare(self, ref, timeout=900):
        from posture.mirror import ScanTarget

        hexd = (ref.digest or "sha256:" + "0" * 64).split(":", 1)[1]
        path = f"oci-dir:/tmp/posture-test-cache/images/{ref.repository.replace('/', '-')}-{hexd[:12]}"
        return ScanTarget(path, False, True, ref.pullable, digest_verified=bool(ref.digest),
                          mirror_digest=ref.digest)


@pytest.fixture(scope="module")
async def env(tmp_path_factory):
    vex_dir = tmp_path_factory.mktemp("vex")
    url = os.environ["TEST_DATABASE_URL"]
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache", "VEX_BUILTIN_DIR": "", "VEX_DIR": str(vex_dir)})
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
    yield {"client": client, "sm": get_sessionmaker(), "settings": get_settings(), "vex_dir": vex_dir}
    await client.aclose()
    await dispose_engine()
    set_authenticator(None)
    for k in ("VEX_BUILTIN_DIR", "VEX_DIR"):
        os.environ.pop(k, None)
    get_settings.cache_clear()


def worker(env):
    w = make_worker(env)
    w.mirror = LocalMirror()
    return w


async def _scan(env, force=False):
    c = env["client"]
    r = await c.post("/scans", json={"force": True} if force else {})
    assert r.status_code == 202
    assert await worker(env).poll_once() is True
    sc = (await c.get(f"/scans/{r.json()['id']}")).json()
    assert sc["status"] == "done", sc
    return sc


async def test_vex_suppresses_across_api_and_reports(env):
    c = env["client"]
    await _scan(env)
    alpine = next(i for i in (await c.get("/images")).json()["items"] if "alpine" in i["ref"])
    before = (await c.get(f"/images/{alpine['id']}")).json()
    s0 = (await c.get("/summary")).json()
    assert s0["vexSuppressed"] == 0 and all(f["vexStatus"] is None for f in before["findings"])
    vulns0 = (await c.get("/vulnerabilities")).json()["total"]
    si2_0 = {x["control"]: x for x in (await c.get("/compliance/controls")).json()}["SI-2"]["findingsOpen"]

    (env["vex_dir"] / "site.vex.json").write_text(json.dumps(VEX))
    sc = await _scan(env, force=True)
    assert any("suppressed by VEX" in line for line in sc["log"])

    after = (await c.get(f"/images/{alpine['id']}")).json()
    assert after["findingsTotal"] == before["findingsTotal"]  # kept, not dropped
    f = next(x for x in after["findings"] if x["vulnId"] == "CVE-2024-6119")
    assert f["vexStatus"] == "not_affected" and f["suppressed"] is True and f["slaOverdue"] is False
    assert f["vexJustification"] == "vulnerable_code_not_in_execute_path"
    assert f["vexSource"] == "site.vex.json (https://example.org/vex/site-2026-10)"
    assert "never reached" in f["vexDetail"]
    inv = next(x for x in after["findings"] if x["vulnId"] == "CVE-2023-42363")
    assert inv["vexStatus"] == "under_investigation" and inv["suppressed"] is False
    assert after["findingsSummary"]["vexSuppressed"] == 1
    # score and counts exclude the suppressed finding
    assert after["score"] > before["score"]
    assert after["severityCounts"]["high"] == before["severityCounts"]["high"] - 1

    sup = (await c.get(f"/images/{alpine['id']}", params={"vex": "suppressed"})).json()
    assert [x["vulnId"] for x in sup["findings"]] == ["CVE-2024-6119"] and sup["findingsTotal"] == 1
    op = (await c.get(f"/images/{alpine['id']}", params={"vex": "open"})).json()
    assert op["findingsTotal"] == before["findingsTotal"] - 1
    assert "CVE-2024-6119" not in {x["vulnId"] for x in op["findings"]}
    assert (await c.get(f"/images/{alpine['id']}", params={"vex": "maybe"})).status_code == 422

    s1 = (await c.get("/summary")).json()
    assert s1["vexSuppressed"] == 1 and s1["counts"]["high"] == s0["counts"]["high"] - 1
    vulns = (await c.get("/vulnerabilities")).json()
    assert vulns["total"] == vulns0 - 1 and "CVE-2024-6119" not in {v["vulnId"] for v in vulns["items"]}
    si2 = {x["control"]: x for x in (await c.get("/compliance/controls")).json()}["SI-2"]["findingsOpen"]
    assert si2 == si2_0 - 1

    rows = list(csv.DictReader(io.StringIO((await c.get("/export", params={"format": "csv"})).text)))
    r = next(x for x in rows if x["vulnId"] == "CVE-2024-6119")
    assert r["vexStatus"] == "not_affected" and r["vexJustification"] == "vulnerable_code_not_in_execute_path"

    from posture.reports.registry import generate
    from posture.reports.snapshot import build_snapshot

    async with env["sm"]() as session:
        snap = await build_snapshot(session, None, None)
    rec = next(x for x in snap.findings if x.vuln_id == "CVE-2024-6119")
    assert rec.status == "not_affected" and rec.vex_justification == "vulnerable_code_not_in_execute_path"
    cdx = json.loads(generate("vuln-export", "cyclonedx-vex", snap, {}).content)
    e = next(v for v in cdx["vulnerabilities"] if v["id"] == "CVE-2024-6119")
    assert e["analysis"]["state"] == "not_affected" and e["analysis"]["justification"] == "code_not_reachable"
    poam = generate("poam", "csv", snap, {"poamGranularity": "finding", "poamVariant": "generic"})
    assert "CVE-2024-6119" not in poam.content.decode("utf-8-sig")
    assert "CVE-2023-42363" in poam.content.decode("utf-8-sig")  # under_investigation stays open


async def test_vex_removed_reopens_on_next_scan(env):
    c = env["client"]
    (env["vex_dir"] / "site.vex.json").unlink()
    await _scan(env, force=True)
    alpine = next(i for i in (await c.get("/images")).json()["items"] if "alpine" in i["ref"])
    d = (await c.get(f"/images/{alpine['id']}")).json()
    assert d["findingsSummary"]["vexSuppressed"] == 0
    assert all(f["vexStatus"] is None for f in d["findings"])
    assert (await c.get("/summary")).json()["vexSuppressed"] == 0

