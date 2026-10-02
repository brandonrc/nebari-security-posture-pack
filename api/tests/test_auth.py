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
