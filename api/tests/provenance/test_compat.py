"""provenance-collector-pack API aliases (their internal/dashboard/*_test.go cases), DB stubbed."""

from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from posture.auth import Authenticator, User, set_authenticator
from posture.config import Settings
from posture.db.session import get_session
from posture.routers import provenance_compat as compat

from .test_report import their_sample

SCAN = SimpleNamespace(id=7, finished_at=datetime(2025, 6, 15, 6, 0, 0, tzinfo=UTC), started_at=None, created_at=None)


@pytest.fixture
def stub_db(monkeypatch):
    state = {"scans": [SCAN], "enqueued": []}

    async def report_scans(session, limit=50):
        return state["scans"]

    async def find_scan(session, filename):
        if not state["scans"]:
            return None
        if filename in ("latest", "provenance-latest.json", "provenance-20250615-060000.json"):
            return state["scans"][0]
        return None

    async def load_report(session, scan, cluster_name):
        return their_sample()

    async def cluster_name(session):
        return "test-cluster"

    monkeypatch.setattr(compat, "report_scans", report_scans)
    monkeypatch.setattr(compat, "find_scan", find_scan)
    monkeypatch.setattr(compat, "load_report", load_report)
    monkeypatch.setattr(compat, "_cluster_name", cluster_name)

    from posture.routers import scans as scans_router

    async def create_scan(body, user, session):
        if state.get("busy"):
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": "a scan is already running", "scanId": 1}, status_code=409)
        state["enqueued"].append(user.username)
        return {"id": 42}

    monkeypatch.setattr(scans_router, "create_scan", create_scan)
    return state


def _app(auth_mode="disabled"):
    set_authenticator(Authenticator(Settings(auth_mode=auth_mode, admin_groups=["admin"],
                                             oidc_issuers=["https://kc/realms/nebari"])))
    app = FastAPI()
    compat.include(app)

    async def no_session():
        yield None

    app.dependency_overrides[get_session] = no_session
    return app


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


@pytest.fixture(autouse=True)
def _reset_auth():
    yield
    set_authenticator(None)


async def test_healthz():
    async with _client(_app()) as c:
        r = await c.get("/healthz")
    assert r.status_code == 200 and r.headers["content-type"] == "application/json" and r.json() == {"status": "ok"}


async def test_list_reports(stub_db):
    async with _client(_app()) as c:
        r = await c.get("/api/reports")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and list(body[0]) == ["filename", "generatedAt", "summary", "clusterName"]
    assert body[0]["filename"] == "provenance-20250615-060000.json"
    assert body[0]["generatedAt"] == "2025-06-15T06:00:00Z" and body[0]["summary"]["totalImages"] == 1
    assert body[0]["clusterName"] == "test-cluster" and r.text.endswith("\n")


async def test_list_reports_empty_is_array_not_null(stub_db):
    stub_db["scans"] = []
    async with _client(_app()) as c:
        r = await c.get("/api/reports")
    assert r.status_code == 200 and r.json() == []


@pytest.mark.parametrize("path", ["/api/reports/latest", "/api/reports/provenance-latest.json",
                                  "/api/reports/provenance-20250615-060000.json"])
async def test_get_report(stub_db, path):
    async with _client(_app()) as c:
        r = await c.get(path)
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    doc = r.json()
    assert list(doc) == ["metadata", "images", "helmReleases", "summary"]
    assert r.text.startswith('{\n  "metadata": {\n    "generatedAt": "2025-06-15T06:00:00Z"')


async def test_get_report_not_found_and_traversal(stub_db):
    async with _client(_app()) as c:
        nf = await c.get("/api/reports/provenance-20200101-000000.json")
        bad = await c.get("/api/reports/..secret")
    assert nf.status_code == 404 and nf.text == "report not found\n" and nf.headers["content-type"].startswith("text/plain")
    assert bad.status_code == 400 and bad.text == "invalid filename\n"


@pytest.mark.parametrize("q,ct,needle", [("format=csv", "text/csv", "Image,Namespace,"),
                                         ("", "text/csv", "nginx:1.27"),
                                         ("format=markdown", "text/markdown", "# Provenance Report"),
                                         ("format=md", "text/markdown", "## Helm Releases"),
                                         ("format=json", "application/json", '"summary"'),
                                         ("format=csv&filename=provenance-20250615-060000.json", "text/csv", "nginx")])
async def test_export(stub_db, q, ct, needle):
    async with _client(_app()) as c:
        r = await c.get(f"/api/export?{q}")
    assert r.status_code == 200 and r.headers["content-type"] == ct and needle in r.text
    if ct != "application/json":
        assert "provenance-report." in r.headers["content-disposition"]


@pytest.mark.parametrize("q,status,text", [("format=xml", 400, "unsupported format: use csv or markdown\n"),
                                           ("filename=../../etc/passwd", 400, "invalid filename\n"),
                                           ("filename=provenance-19990101-000000.json", 404, "report not found\n")])
async def test_export_errors(stub_db, q, status, text):
    async with _client(_app()) as c:
        r = await c.get(f"/api/export?{q}")
    assert r.status_code == status and r.text == text


async def test_export_no_report(stub_db):
    stub_db["scans"] = []
    async with _client(_app()) as c:
        assert (await c.get("/api/export")).status_code == 404


async def test_reads_require_admin_on_main_listener(stub_db):
    async with _client(_app("oidc")) as c:
        assert (await c.get("/api/reports")).status_code == 401
        assert (await c.get("/api/reports/latest")).status_code == 401
        assert (await c.get("/api/export")).status_code == 401
        assert (await c.get("/healthz")).status_code == 200


async def test_internal_app_is_unauthenticated_and_read_only(stub_db):
    set_authenticator(Authenticator(Settings(auth_mode="oidc", oidc_issuers=["https://kc/realms/nebari"])))
    app = compat.internal_app()

    async def no_session():
        yield None

    app.dependency_overrides[get_session] = no_session
    async with _client(app) as c:
        assert (await c.get("/api/reports/latest")).json()["summary"]["totalImages"] == 1
        assert (await c.get("/api/reports")).status_code == 200
        assert (await c.get("/api/export?format=csv")).status_code == 200
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.post("/api/scan")).status_code in (404, 405)
        assert (await c.get("/api/me")).status_code == 404
        assert (await c.get("/api/v1/summary")).status_code == 404


async def test_me_anonymous_and_admin():
    async with _client(_app("oidc")) as c:
        anon = (await c.get("/api/me")).json()
    assert anon == {"authEnabled": True, "canRunScan": False, "features": {"timelineDeltas": True}}
    app = _app("oidc")

    async def fake_auth(request):
        return User("alice", "alice@example.com", ["admin"], True)

    from posture.auth import get_authenticator

    get_authenticator().authenticate = fake_auth
    async with _client(app) as c:
        me = (await c.get("/api/me")).json()
    assert me == {"authEnabled": True, "email": "alice@example.com", "groups": ["admin"], "canRunScan": True,
                  "features": {"timelineDeltas": True}}


async def test_scan_csrf_auth_and_conflict(stub_db):
    app = _app("disabled")
    async with _client(app) as c:
        assert (await c.get("/api/scan")).status_code == 405
        r = await c.post("/api/scan")
        assert r.status_code == 403 and r.text == "cross-origin requests not allowed\n"
        r = await c.post("/api/scan", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200 and r.json()["jobName"] == "posture-scan-42" and "namespace" in r.json()
        stub_db["busy"] = True
        r = await c.post("/api/scan", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 409
    async with _client(_app("oidc")) as c:
        r = await c.post("/api/scan", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403 and "admin group" in r.text
    assert stub_db["enqueued"] == ["dev"]


async def test_internal_listener_starts_only_when_configured():
    assert await compat.start_internal(Settings()) is None
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = await compat.start_internal(Settings(provenance_compat_internal_port=port))
    try:
        import asyncio

        for _ in range(50):
            if srv.server.started:
                break
            await asyncio.sleep(0.05)
        async with httpx.AsyncClient() as c:
            r = await c.get(f"http://127.0.0.1:{port}/healthz")
        assert r.json() == {"status": "ok"}
    finally:
        await srv.stop()


def test_empty_port_env_is_disabled(monkeypatch):
    monkeypatch.setenv("PROVENANCE_COMPAT_INTERNAL_PORT", "")
    assert Settings().provenance_compat_internal_port is None
