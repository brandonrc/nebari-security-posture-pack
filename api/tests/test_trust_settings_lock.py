"""Security review L5: cosign trust anchors are not editable at runtime when locked."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from posture import app_settings
from posture.auth import Authenticator, set_authenticator
from posture.config import Settings
from posture.db.session import get_session
from posture.routers import settings as settings_router


class FakeSession:
    def __init__(self):
        self.row = None

    async def get(self, model, key):
        return self.row

    def add(self, row):
        self.row = row

    async def commit(self):
        pass


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PROVENANCE_COSIGN_PUBLIC_KEY", "awskms:///alias/real")
    from posture.config import get_settings

    get_settings.cache_clear()
    set_authenticator(Authenticator(Settings(auth_mode="disabled", posture_dev=True)))
    session = FakeSession()
    app = FastAPI()
    app.include_router(settings_router.router)

    async def _session():
        yield session

    app.dependency_overrides[get_session] = _session
    yield TestClient(app), session
    set_authenticator(None)
    get_settings.cache_clear()


def test_locked_trust_fields_refused(client, monkeypatch):
    c, session = client
    monkeypatch.setenv("PROVENANCE_TRUST_SETTINGS_LOCKED", "true")
    for field in ("cosignPublicKey", "cosignCertificateIdentityRegexp", "cosignCertificateOidcIssuerRegexp"):
        r = c.put("/settings", json={"provenance": {field: ".*"}})
        assert r.status_code == 403 and field in r.json()["detail"]
    r = c.put("/settings", json={"provenance": {"cosign_public_key": "/etc/passwd"}})
    assert r.status_code == 403
    # other provenance toggles stay editable; re-sending the current value is fine (UI round-trips)
    r = c.put("/settings", json={"provenance": {"checkSbom": False, "cosignPublicKey": "awskms:///alias/real"}})
    assert r.status_code == 200 and r.json()["provenance"]["checkSbom"] is False


def test_locked_ignores_previously_stored_values(client, monkeypatch):
    c, session = client
    r = c.put("/settings", json={"provenance": {"cosignCertificateIdentityRegexp": ".*",
                                                "cosignCertificateOidcIssuerRegexp": ".*"}})
    assert r.status_code == 200 and r.json()["provenance"]["cosignCertificateIdentityRegexp"] == ".*"
    monkeypatch.setenv("PROVENANCE_TRUST_SETTINGS_LOCKED", "true")
    got = c.get("/settings").json()["provenance"]
    assert got["cosignCertificateIdentityRegexp"] == "" and got["cosignPublicKey"] == "awskms:///alias/real"


def test_unlocked_is_editable(client, monkeypatch):
    c, _ = client
    monkeypatch.delenv("PROVENANCE_TRUST_SETTINGS_LOCKED", raising=False)
    assert not app_settings.trust_settings_locked()
    r = c.put("/settings", json={"provenance": {"cosignPublicKey": "awskms:///alias/other"}})
    assert r.status_code == 200 and r.json()["provenance"]["cosignPublicKey"] == "awskms:///alias/other"
