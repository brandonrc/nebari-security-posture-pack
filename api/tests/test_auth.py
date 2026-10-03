import base64
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from posture.auth import Authenticator, JWKSCache, User, current_user, require_admin, set_authenticator
from posture.config import Settings

ISS = "https://keycloak.example/auth/realms/nebari"


def b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def make_key(kid: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    return key, {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": b64(pub.n), "e": b64(pub.e)}


KEY1, JWK1 = make_key("k1")
KEY2, JWK2 = make_key("k2")
OTHER, _ = make_key("k1")


def token(key=KEY1, kid="k1", **claims):
    base = {"iss": ISS, "sub": "u1", "preferred_username": "alice", "email": "alice@example.com",
            "groups": ["/admin", "users"], "exp": int(time.time()) + 300, "iat": int(time.time())}
    base.update(claims)
    return jwt.encode(base, key, algorithm="RS256", headers={"kid": kid})


class JwksServer:
    def __init__(self, keys):
        self.keys = keys
        self.calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={"keys": self.keys})


def make_client(keys=None, **settings_kw):
    server = JwksServer(keys or [JWK1])
    http = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    settings = Settings(auth_mode="oidc", oidc_issuers=[ISS, "http://keycloak-internal/auth/realms/nebari"],
                        admin_groups=["admin"], oidc_jwks_url="http://jwks", **settings_kw)
    auth = Authenticator(settings, JWKSCache("http://jwks", 600, http=http))
    set_authenticator(auth)
    app = FastAPI()

    @app.get("/me")
    async def me(user: User = Depends(current_user)):
        return user.as_dict()

    @app.get("/admin")
    async def admin(user: User = Depends(require_admin)):
        return {"ok": True}

    return TestClient(app), server, auth


@pytest.fixture(autouse=True)
def _reset():
    yield
    set_authenticator(None)


def test_bearer_token_admin():
    client, server, _ = make_client()
    r = client.get("/admin", headers={"Authorization": f"Bearer {token()}"})
    assert r.status_code == 200
    me = client.get("/me", headers={"Authorization": f"Bearer {token()}"}).json()
    assert me == {"username": "alice", "email": "alice@example.com", "groups": ["admin", "users"], "isAdmin": True}


def test_cookie_tokens():
    client, _, _ = make_client()
    assert client.get("/admin", cookies={"NebariIdToken": token()}).status_code == 200
    client.cookies.clear()  # noqa
    assert client.get("/admin", cookies={"IdToken-abc123": token()}).status_code == 200
    client.cookies.clear()  # noqa
    assert client.get("/admin", cookies={"AccessToken-abc": token()}).status_code == 401


def test_missing_and_invalid_tokens_401():
    client, _, _ = make_client()
    assert client.get("/admin").json() == {"detail": "authentication required"}
    assert client.get("/admin").status_code == 401
    assert client.get("/admin", headers={"Authorization": "Bearer garbage"}).status_code == 401
    forged = token(key=OTHER)
    assert client.get("/admin", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    expired = token(exp=int(time.time()) - 3600)
    assert client.get("/admin", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    bad_iss = token(iss="https://evil.example/realms/x")
    assert client.get("/admin", headers={"Authorization": f"Bearer {bad_iss}"}).status_code == 401
    none_alg = jwt.encode({"iss": ISS, "exp": int(time.time()) + 60}, None, algorithm="none")
    assert client.get("/admin", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


def test_non_admin_403_but_me_allowed():
    client, _, _ = make_client()
    t = token(groups=["/users", "analyst"])
    r = client.get("/admin", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 403 and r.json() == {"detail": "admin group required"}
    me = client.get("/me", headers={"Authorization": f"Bearer {t}"}).json()
    assert me["isAdmin"] is False and me["groups"] == ["users", "analyst"]


def test_internal_issuer_accepted():
    client, _, _ = make_client()
    t = token(iss="http://keycloak-internal/auth/realms/nebari")
    assert client.get("/admin", headers={"Authorization": f"Bearer {t}"}).status_code == 200


def test_jwks_cached_and_refetched_on_unknown_kid(monkeypatch):
    client, server, auth = make_client(keys=[JWK1])
    for _ in range(3):
        assert client.get("/admin", headers={"Authorization": f"Bearer {token()}"}).status_code == 200
    assert server.calls == 1
    # key rotation: new kid appears in JWKS
    server.keys = [JWK1, JWK2]
    monkeypatch.setattr("posture.auth.REFETCH_MIN_INTERVAL", 0)
    assert client.get("/admin", headers={"Authorization": f"Bearer {token(KEY2, 'k2')}"}).status_code == 200
    assert server.calls == 2


def test_auth_disabled_bypass():
    settings = Settings(auth_mode="disabled", admin_groups=["admin"])
    set_authenticator(Authenticator(settings))
    app = FastAPI()

    @app.get("/admin")
    async def admin(user: User = Depends(require_admin)):
        return user.as_dict()

    assert TestClient(app).get("/admin").json()["isAdmin"] is True


def test_settings_parsing(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUERS", "https://a/realms/n, http://b/realms/n")
    monkeypatch.setenv("ADMIN_GROUPS", "/admin,security")
    monkeypatch.setenv("EXCLUDED_NAMESPACES", "")
    monkeypatch.setenv("MIRROR_REWRITE", "localhost:32000=registry.container-registry.svc.cluster.local:5000")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h/db")
    s = Settings()
    assert s.oidc_issuers == ["https://a/realms/n", "http://b/realms/n"]
    assert s.admin_group_set == {"admin", "security"}
    assert s.excluded_namespaces == []
    assert s.rewrite_map == {"localhost:32000": "registry.container-registry.svc.cluster.local:5000"}
    assert s.database_url == "postgresql+asyncpg://u:p@h/db"


def test_report_routes_are_admin_only():
    """The real app mounts /reports* and /compliance/stig behind require_admin."""
    _, _, auth = make_client()
    from posture.main import create_app

    set_authenticator(auth)
    client = TestClient(create_app())
    user = {"Authorization": f"Bearer {token(groups=['/users'])}"}
    for method, path in [("GET", "/api/v1/reports/types"), ("GET", "/api/v1/reports"),
                         ("POST", "/api/v1/reports"), ("GET", "/api/v1/reports/x"),
                         ("GET", "/api/v1/reports/x/download"), ("DELETE", "/api/v1/reports/x"),
                         ("GET", "/api/v1/compliance/stig")]:
        assert client.request(method, path).status_code == 401, path
        r = client.request(method, path, headers=user, json={"type": "poam", "format": "csv"})
        assert r.status_code == 403 and r.json() == {"detail": "admin group required"}, path
    admin = {"Authorization": f"Bearer {token()}"}
    assert client.get("/api/v1/reports/types", headers=admin).status_code == 200


# ---------------------------------------------------------------- security review H1 / L3 / L4
def _get(client, tok):
    return client.get("/admin", headers={"Authorization": f"Bearer {tok}"})


def test_oidc_without_issuers_refuses_to_start():
    from posture.auth import AuthConfigError

    with pytest.raises(AuthConfigError, match="OIDC_ISSUERS"):
        Authenticator(Settings(auth_mode="oidc", oidc_issuers=[]))


def test_auth_disabled_requires_posture_dev(monkeypatch):
    from posture.auth import AuthConfigError

    monkeypatch.delenv("POSTURE_DEV", raising=False)
    with pytest.raises(AuthConfigError, match="POSTURE_DEV"):
        Authenticator(Settings(auth_mode="disabled"))
    Authenticator(Settings(auth_mode="disabled", posture_dev=True))  # allowed


def test_unknown_auth_mode_refuses_to_start():
    from posture.auth import AuthConfigError

    with pytest.raises(AuthConfigError):
        Authenticator(Settings(auth_mode="none", oidc_issuers=[ISS]))


def test_audience_wrong_and_missing_rejected():
    client, _, _ = make_client(oidc_client_ids=["security-posture-security-posture"])
    assert _get(client, token(aud="other-app", azp="other-app")).status_code == 401
    assert _get(client, token()).status_code == 401  # no aud, no azp
    # access token: aud=account, azp=our client -> accepted
    assert _get(client, token(aud="account", azp="security-posture-security-posture")).status_code == 200
    # id token: aud=our client
    assert _get(client, token(aud="security-posture-security-posture")).status_code == 200
    assert _get(client, token(aud=["account", "security-posture-security-posture"], azp="x")).status_code == 200


def test_oidc_audiences_and_legacy_audience_merge():
    s = Settings(auth_mode="oidc", oidc_issuers=[ISS], oidc_audiences=["a"], oidc_client_ids=["b"],
                 oidc_audience="c")
    assert s.accepted_audiences == ["a", "b", "c"]
    client, _, _ = make_client(oidc_audiences=["grafana"])
    assert _get(client, token(azp="grafana")).status_code == 200
    assert _get(client, token(azp="jupyterhub")).status_code == 401


def test_no_audience_configured_skips_check_with_warning():
    client, _, auth = make_client()
    assert auth.audiences == set()
    assert _get(client, token(aud="anything")).status_code == 200


def test_alg_confusion_hs256_with_rsa_public_key_rejected():
    from cryptography.hazmat.primitives import serialization

    client, _, _ = make_client()
    pem = KEY1.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claims = {"iss": ISS, "exp": int(time.time()) + 300, "groups": ["admin"]}
    # PyJWT refuses PEM keys as HMAC secrets, so sign the HS256 token by hand
    import hashlib
    import hmac
    import json as _json

    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    head = b64u(_json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64u(_json.dumps(claims).encode())
    sig = b64u(hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    assert _get(client, f"{head}.{body}.{sig}").status_code == 401


def test_alg_mismatch_with_jwk_alg_rejected():
    client, _, _ = make_client()
    t = jwt.encode({"iss": ISS, "exp": int(time.time()) + 300, "groups": ["admin"]}, KEY1, algorithm="PS256",
                   headers={"kid": "k1"})
    assert _get(client, t).status_code == 401  # JWK pins RS256


def test_missing_exp_iss_and_future_nbf_rejected():
    client, _, _ = make_client()
    now = int(time.time())
    no_exp = jwt.encode({"iss": ISS, "groups": ["admin"]}, KEY1, algorithm="RS256", headers={"kid": "k1"})
    no_iss = jwt.encode({"exp": now + 300, "groups": ["admin"]}, KEY1, algorithm="RS256", headers={"kid": "k1"})
    assert _get(client, no_exp).status_code == 401
    assert _get(client, no_iss).status_code == 401
    assert _get(client, token(nbf=now + 3600)).status_code == 401
    assert _get(client, token(nbf=now - 10)).status_code == 200


def _client_with_jwks(handler):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = Settings(auth_mode="oidc", oidc_issuers=[ISS], oidc_jwks_url="http://jwks")
    set_authenticator(Authenticator(settings, JWKSCache("http://jwks", 600, http=http)))
    app = FastAPI()

    @app.get("/admin")
    async def admin(user: User = Depends(require_admin)):
        return {"ok": True}

    return TestClient(app, raise_server_exceptions=False)


def test_jwks_http_500_is_401():
    client = _client_with_jwks(lambda r: httpx.Response(500, text="boom"))
    assert _get(client, token()).status_code == 401


def test_jwks_non_json_is_401():
    client = _client_with_jwks(lambda r: httpx.Response(200, text="<html>login</html>"))
    assert _get(client, token()).status_code == 401
    client = _client_with_jwks(lambda r: httpx.Response(200, json=["not", "an", "object"]))
    assert _get(client, token()).status_code == 401


async def test_jwks_lock_not_held_during_fetch(monkeypatch):
    """Concurrent callers share one in-flight fetch; once cached, an expired TTL refreshes in the
    background and does not block requests on a slow JWKS endpoint."""
    import asyncio

    release = asyncio.Event()
    calls = 0

    async def slow(request):
        nonlocal calls
        calls += 1
        if calls > 1:
            await release.wait()
        return httpx.Response(200, json={"keys": [JWK1]})

    cache = JWKSCache("http://jwks", ttl=0, http=httpx.AsyncClient(transport=httpx.MockTransport(slow)))
    monkeypatch.setattr("posture.auth.REFETCH_MIN_INTERVAL", 0)
    await asyncio.gather(*(cache.get_key("k1") for _ in range(5)))
    assert calls == 1  # single flight
    # TTL expired, background refresh hangs: callers still get the cached key immediately
    key = await asyncio.wait_for(cache.get_key("k1"), timeout=1)
    assert key is not None
    await asyncio.sleep(0)
    assert calls == 2 and not cache._lock.locked()
    release.set()
    await cache._inflight
