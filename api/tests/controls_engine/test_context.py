"""Keycloak admin client (master-realm vs realm-admin credentials), K8s pagination, context wiring."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from posture.controls_engine.context import (
    EngineConfig,
    KeycloakAdmin,
    KeycloakError,
    build_context,
    list_items,
)

from .fakes import FakeKube

BASE = "http://kc/auth"


def kc_transport(valid: dict[str, dict], calls: list):
    """valid: realm -> expected form fields for a 200 token response."""

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path.endswith("/protocol/openid-connect/token"):
            realm = req.url.path.split("/realms/")[1].split("/")[0]
            form = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            want = valid.get(realm)
            if want and all(form.get(k) == v for k, v in want.items()):
                return httpx.Response(200, json={"access_token": f"tok-{realm}", "expires_in": 300})
            return httpx.Response(401, json={"error": "invalid_grant"})
        if req.url.path == "/auth/admin/realms/nebari":
            assert req.headers["authorization"].startswith("Bearer tok-")
            return httpx.Response(200, json={"realm": "nebari", "bruteForceProtected": True})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


async def test_master_realm_admin_fallback():
    calls: list = []
    http = httpx.AsyncClient(transport=kc_transport({"master": {"username": "admin", "password": "pw"}}, calls))
    kc = KeycloakAdmin(http, BASE, "nebari", {"username": "admin", "password": "pw"})
    assert (await kc.get(""))["realm"] == "nebari"
    assert kc.token_realm == "master"
    tokens = [c for c in calls if c[1].endswith("/token")]
    assert [t[1].split("/")[3] for t in tokens] == ["nebari", "master"]  # target realm first, then master
    await kc.get("")
    assert len([c for c in calls if c[1].endswith("/token")]) == 2  # token cached


async def test_realm_admin_credentials():
    calls: list = []
    http = httpx.AsyncClient(transport=kc_transport({"nebari": {"username": "realm-admin"}}, calls))
    kc = KeycloakAdmin(http, BASE, "nebari", {"username": "realm-admin", "password": "x"})
    await kc.get("")
    assert kc.token_realm == "nebari" and len(calls) == 2


async def test_client_credentials_and_pinned_realm():
    calls: list = []
    http = httpx.AsyncClient(transport=kc_transport(
        {"master": {"grant_type": "client_credentials", "client_id": "posture", "client_secret": "s3"}}, calls))
    kc = KeycloakAdmin(http, BASE, "nebari", {"client-id": "posture", "client-secret": "s3", "realm": "master"})
    await kc.get("")
    assert kc.token_realm == "master" and [c[1] for c in calls][0] == "/auth/realms/master/protocol/openid-connect/token"


async def test_login_failure_is_cached():
    calls: list = []
    http = httpx.AsyncClient(transport=kc_transport({}, calls))
    kc = KeycloakAdmin(http, BASE, "nebari", {"username": "a", "password": "b"})
    with pytest.raises(KeycloakError, match="nebari: HTTP 401; master: HTTP 401"):
        await kc.get("")
    with pytest.raises(KeycloakError):
        await kc.get("/events/config")
    assert len(calls) == 2


async def test_missing_credentials():
    kc = KeycloakAdmin(httpx.AsyncClient(), BASE, "nebari", {"username": "a"})
    with pytest.raises(KeycloakError, match="username\\+password"):
        await kc.token()


async def test_list_items_follows_continue():
    api = FakeKube({"/api/v1/pods": [{"metadata": {"name": str(i)}} for i in range(7)]}, page_size=3)
    items = await list_items(api, "/api/v1/pods")
    assert [i["metadata"]["name"] for i in items] == [str(i) for i in range(7)]
    assert api.calls.count("/api/v1/pods") == 3


async def test_build_context_reads_admin_secret():
    secret = {"data": {k: base64.b64encode(v.encode()).decode() for k, v in
                       {"username": "admin", "password": "pw"}.items()}}
    api = FakeKube({"/api/v1/namespaces/keycloak/secrets/nebari-realm-admin-credentials": secret})
    ctx = await build_context(EngineConfig(), {}, k8s=api, http=httpx.AsyncClient())
    assert isinstance(ctx.keycloak, KeycloakAdmin) and ctx.keycloak.creds["password"] == "pw"
    assert ctx.keycloak_error is None
    ctx = await build_context(EngineConfig(keycloak_admin_secret_name="missing"), {}, k8s=api,
                              http=httpx.AsyncClient())
    assert ctx.keycloak is None and "unreadable" in ctx.keycloak_error
    ctx = await build_context(EngineConfig(keycloak_url=""), {}, k8s=api, http=httpx.AsyncClient())
    assert ctx.keycloak is None and "not configured" in ctx.keycloak_error


async def test_memo_shares_results_and_errors():
    from posture.controls_engine.context import EngineContext

    ctx = EngineContext(config=EngineConfig(), k8s=FakeKube({"/api/v1/nodes": []}))
    await ctx.k8s_list("/api/v1/nodes")
    await ctx.k8s_list("/api/v1/nodes")
    assert ctx.k8s.calls.count("/api/v1/nodes") == 1
    assert await ctx.k8s_list_optional("/apis/x/v1/y") is None
    json.dumps(ctx.config.__dict__)  # config stays serialisable for evidence
