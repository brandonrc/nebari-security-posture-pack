"""Security review M6: cookie-authenticated state-changing /api/v1 requests must be same-origin."""

import pytest
from fastapi.testclient import TestClient

from posture.auth import Authenticator, set_authenticator
from posture.config import Settings
from posture.main import create_app


@pytest.fixture
def client():
    set_authenticator(Authenticator(Settings(auth_mode="disabled", posture_dev=True)))
    yield TestClient(create_app(), base_url="https://security.example.com")
    set_authenticator(None)


COOKIE = {"Cookie": "IdToken-abc=x; OauthHMAC-abc=y"}
# DELETE of an unknown report: reaches the router (404) only when the CSRF guard lets it through
PATH = "/api/v1/reports/does-not-exist"


def _status(client, headers):
    return client.request("DELETE", PATH, headers=headers).status_code


def test_cross_site_cookie_post_blocked(client):
    r = client.post("/api/v1/scans", headers={**COOKIE, "Sec-Fetch-Site": "same-site",
                                               "Content-Type": "text/plain"})
    assert r.status_code == 403 and r.json() == {"detail": "cross-site request blocked"}
    assert client.post("/api/v1/compliance/assertions/run",
                       headers={**COOKIE, "Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_cookie_without_fetch_metadata_or_origin_blocked(client):
    assert _status(client, COOKIE) == 403


@pytest.mark.parametrize("site", ["same-origin", "none"])
def test_same_origin_fetch_metadata_allowed(client, site):
    assert _status(client, {**COOKIE, "Sec-Fetch-Site": site}) != 403


def test_matching_origin_allowed_foreign_origin_blocked(client):
    assert _status(client, {**COOKIE, "Origin": "https://security.example.com"}) != 403
    assert _status(client, {**COOKIE, "Origin": "https://jupyter.example.com"}) == 403
    assert _status(client, {**COOKIE, "Origin": "null"}) == 403
    assert _status(client, {**COOKIE, "Origin": "https://evil.example", "X-Forwarded-Host": "security.example.com"}) == 403


def test_bearer_only_clients_exempt(client):
    assert _status(client, {"Authorization": "Bearer abc"}) != 403
    assert _status(client, {}) != 403


def test_safe_methods_and_non_api_paths_exempt(client):
    assert client.get("/api/v1/reports/types", headers={**COOKIE, "Sec-Fetch-Site": "cross-site"}).status_code != 403
    assert client.get("/healthz", headers={**COOKIE, "Sec-Fetch-Site": "cross-site"}).status_code == 200
