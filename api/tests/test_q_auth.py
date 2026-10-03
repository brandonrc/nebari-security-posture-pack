"""M7/M8: route-table authorization lock-in and the remaining JWT/JWKS negative cases.

The route-table test introspects the real app, so a router mounted on the wrong group (or a new
public route) fails CI until it is added to the explicit allowlists below.
"""

from __future__ import annotations

import re
import time

import httpx
import jwt
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from posture import auth as auth_mod
from posture.auth import AuthError, JWKSCache, normalize_groups, set_authenticator
from tests.test_auth import ISS, JWK1, JWK2, KEY1, KEY2, make_client, make_key, token

# No authentication at all (probes).
PUBLIC = {
    ("GET", "/health"), ("GET", "/ready"), ("GET", "/healthz"), ("GET", "/metrics"),
    ("GET", "/api/v1/health"), ("GET", "/api/v1/ready"),
}
# Any authenticated user (not only admins).
AUTHENTICATED = {("GET", "/api/v1/me")}
# provenance-collector-pack compat aliases that authenticate inside the handler (their contract):
# /api/me answers anonymous callers (canRunScan false); /api/scan is Sec-Fetch-Site gated and
# returns 403 (not 401) to anonymous and non-admin callers alike.
SELF_GATED = {("GET", "/api/me"), ("POST", "/api/scan")}


@pytest.fixture(autouse=True)
def _reset():
    yield
    set_authenticator(None)


def _routes(app):
    """(method, path) of every HTTP route, including routes of included routers. FastAPI >= 0.140
    keeps included routers lazy (`_IncludedRouter`); `iter_route_contexts` flattens them."""
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:  # older FastAPI: include_router copies APIRoutes onto the app
        contexts = [r for r in app.routes if isinstance(r, APIRoute)]
    else:
        contexts = list(iter_route_contexts(app.routes))
    for r in contexts:
        for m in sorted((getattr(r, "methods", None) or set()) - {"HEAD", "OPTIONS"}):
            yield m, r.path


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


@pytest.fixture(scope="module")
def app():
    from posture.main import create_app

    return create_app()


def test_route_inventory_is_known(app):
    """Every route is either under /api/v1, a compat alias under /api, or a known probe."""
    routes = set(_routes(app))
    assert len(routes) > 40
    stray = {(m, p) for m, p in routes if not p.startswith("/api/") and (m, p) not in PUBLIC}
    assert not stray, f"routes outside /api with no auth policy: {sorted(stray)}"
    for allow in (PUBLIC | AUTHENTICATED | SELF_GATED):
        assert allow in routes or allow[1] in ("/healthz", "/api/v1/health", "/api/v1/ready", "/metrics"), allow


def test_every_route_requires_auth_and_admin(app):
    _, _, authn = make_client()
    set_authenticator(authn)
    client = TestClient(app, raise_server_exceptions=False)
    user = {"Authorization": f"Bearer {token(groups=['/users'])}"}
    checked = 0
    for method, path in sorted(set(_routes(app))):
        if (method, path) in PUBLIC | SELF_GATED:
            continue
        url = _concrete(path)
        r = client.request(method, url, json={})
        assert r.status_code == 401, f"{method} {path}: unauthenticated -> {r.status_code}"
        r = client.request(method, url, headers=user, json={})
        if (method, path) in AUTHENTICATED:
            assert r.status_code != 403, f"{method} {path} must be open to any signed-in user"
        else:
            assert r.status_code == 403, f"{method} {path}: non-admin -> {r.status_code}"
            assert r.json() == {"detail": "admin group required"}
        checked += 1
    assert checked > 40


def test_self_gated_compat_routes(app):
    _, _, authn = make_client()
    set_authenticator(authn)
    client = TestClient(app)
    anon = client.get("/api/me").json()
    assert anon["canRunScan"] is False and "email" not in anon
    user = client.get("/api/me", headers={"Authorization": f"Bearer {token(groups=['users'])}"}).json()
    assert user["canRunScan"] is False and user["groups"] == ["users"]
    assert client.get("/api/me", headers={"Authorization": f"Bearer {token()}"}).json()["canRunScan"] is True
    same = {"Sec-Fetch-Site": "same-origin"}
    assert client.post("/api/scan", headers=same).status_code == 403
    assert client.post("/api/scan", headers={**same, "Authorization": f"Bearer {token(groups=['users'])}"}).status_code == 403
    assert client.post("/api/scan", headers={"Authorization": f"Bearer {token()}"}).status_code == 403  # no Sec-Fetch-Site


def test_openapi_and_docs_are_admin_only(app):
    _, _, authn = make_client()
    set_authenticator(authn)
    client = TestClient(app)
    for path in ("/api/v1/openapi.json", "/api/v1/docs"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": f"Bearer {token(groups=['users'])}"}).status_code == 403
    assert client.get("/api/v1/openapi.json", headers={"Authorization": f"Bearer {token()}"}).status_code == 200
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404


# ---------------------------------------------------------------- JWT / JWKS negative cases (M8)

def _status(client, tok):
    return client.get("/admin", headers={"Authorization": f"Bearer {tok}"}).status_code


@pytest.mark.parametrize("bad", [
    "not-a-jwt", "a.b.c", "", "Bearer", "eyJhbGciOiJub25lIn0.e30.",
])
def test_garbage_tokens_are_401(bad):
    client, _, _ = make_client()
    r = client.get("/admin", headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer"


def test_unsupported_header_alg_rejected_before_jwks():
    client, server, _ = make_client()
    tok = jwt.encode({"iss": ISS, "exp": int(time.time()) + 60}, "s" * 32, algorithm="HS256", headers={"kid": "k1"})
    assert _status(client, tok) == 401
    assert server.calls == 0  # rejected on the header, no JWKS fetch


def test_expired_within_leeway_accepted_and_beyond_rejected():
    client, _, _ = make_client()
    assert _status(client, token(exp=int(time.time()) - 10)) == 200   # 30 s leeway
    assert _status(client, token(exp=int(time.time()) - 120)) == 401


def test_key_rotation_new_kid_is_fetched():
    client, server, _ = make_client(keys=[JWK1])
    assert _status(client, token()) == 200
    server.keys = [JWK1, JWK2]
    auth_mod_time = time.monotonic
    try:
        # pretend the refetch throttle window has passed
        auth_mod.time.monotonic = lambda: auth_mod_time() + 3600
        assert _status(client, token(key=KEY2, kid="k2")) == 200
    finally:
        auth_mod.time.monotonic = auth_mod_time
    assert server.calls == 2


def test_random_kid_flood_is_throttled():
    """M8: random-kid tokens must not turn into one JWKS fetch each (REFETCH_MIN_INTERVAL)."""
    client, server, _ = make_client()
    assert _status(client, token()) == 200
    for i in range(20):
        assert _status(client, token(kid=f"random-{i}")) == 401
    assert server.calls <= 2


def test_kidless_token_uses_the_single_key_only():
    client, _, _ = make_client(keys=[JWK1])
    tok = jwt.encode({"iss": ISS, "exp": int(time.time()) + 60, "groups": ["admin"]}, KEY1, algorithm="RS256")
    assert _status(client, tok) == 200
    client2, _, _ = make_client(keys=[JWK1, JWK2])
    tok2 = jwt.encode({"iss": ISS, "exp": int(time.time()) + 60, "groups": ["admin"]}, KEY2, algorithm="RS256")
    assert _status(client2, tok2) == 401  # ambiguous: no kid and several keys


def test_encryption_and_malformed_jwks_entries_are_ignored():
    enc = dict(JWK2, use="enc")
    bad = {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"}
    client, _, authn = make_client(keys=[JWK1, enc, bad, "junk"])
    assert _status(client, token()) == 200
    assert set(authn.jwks._keys) == {"k1"}
    assert _status(client, token(key=KEY2, kid="k2")) == 401


async def test_jwks_too_large_and_bad_shape_raise():
    for body in (b'{"keys": "nope"}', b"[1, 2]", b'{"keys": [' + b" " * (auth_mod.MAX_JWKS_BYTES + 1) + b"]}"):
        http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r, b=body: httpx.Response(200, content=b)))
        cache = JWKSCache("http://jwks", http=http)
        with pytest.raises(auth_mod.JWKSError):
            await cache._fetch()


async def test_jwks_fetch_without_injected_client_closes_its_own(monkeypatch):
    real = httpx.AsyncClient
    closed = []

    class Tracking(real):
        async def aclose(self):
            closed.append(True)
            await super().aclose()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: Tracking(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [JWK1]})), **kw))
    cache = JWKSCache("http://jwks")
    assert await cache.get_key("k1") is not None
    assert closed == [True]
    with pytest.raises(AuthError):
        await cache.get_key("nope")


def test_groups_claim_shapes():
    assert normalize_groups(None) == []
    assert normalize_groups("/admin") == ["admin"]  # a single string is accepted (Keycloak mapper quirk)
    assert normalize_groups({"admin": True}) == []
    assert normalize_groups(["/a", " ", "", "b"]) == ["a", "b"]
    client, _, _ = make_client()
    assert _status(client, token(groups="/admin")) == 200
    assert _status(client, token(groups={"admin": 1})) == 403


def test_bearer_beats_cookies_and_empty_bearer_falls_back():
    client, _, _ = make_client()
    good, bad = token(), "garbage"
    client.cookies.set("NebariIdToken", good)
    assert client.get("/admin", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
    assert client.get("/admin", headers={"Authorization": "Bearer "}).status_code == 200


def test_current_user_is_cached_per_request():
    client, server, authn = make_client()
    calls = []
    orig = authn.authenticate

    async def counting(request):
        calls.append(1)
        return await orig(request)

    authn.authenticate = counting
    assert _status(client, token()) == 200
    assert len(calls) == 1  # require_admin -> current_user resolves once


def test_get_authenticator_builds_from_settings(monkeypatch):
    from posture.config import Settings

    monkeypatch.setattr(auth_mod, "get_settings", lambda: Settings(auth_mode="disabled", posture_dev=True))
    set_authenticator(None)
    a = auth_mod.get_authenticator()
    assert a.settings.auth_disabled and auth_mod.get_authenticator() is a


def test_other_kid_rsa_key_cannot_sign():
    other, _ = make_key("k1")
    client, _, _ = make_client()
    assert _status(client, token(key=other)) == 401
