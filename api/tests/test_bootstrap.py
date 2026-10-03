"""posture.bootstrap ensure-secret (chart hook Job replacing Helm `lookup`, review B1)."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from posture import bootstrap


class FakeCore:
    def __init__(self, existing=None, race=False):
        self.secrets = {} if existing is None else {"db": existing}
        self.race = race
        self.calls = []
        self.annotations = {}

    def read_namespaced_secret(self, name, ns):
        self.calls.append(("read", name))
        if name not in self.secrets:
            raise ApiException(status=404)
        return SimpleNamespace(data=dict(self.secrets[name]),
                               metadata=SimpleNamespace(annotations=dict(self.annotations)))

    def create_namespaced_secret(self, ns, body):
        self.calls.append(("create", body["metadata"]["name"]))
        if self.race:
            self.secrets[body["metadata"]["name"]] = {"password": "theirs"}
            raise ApiException(status=409)
        self.secrets[body["metadata"]["name"]] = body["data"]

    def patch_namespaced_secret(self, name, ns, body):
        self.calls.append(("patch", name))
        self.secrets[name].update(body.get("data", {}))
        self.annotations.update(body.get("metadata", {}).get("annotations", {}))


def test_creates_when_missing():
    api = FakeCore()
    assert bootstrap.ensure_secret(api, "ns", "db", ["password", "postgres-password"],
                                   labels={"a": "b"}) == "created"
    data = api.secrets["db"]
    pw = base64.b64decode(data["password"]).decode()
    assert len(pw) == 32 and pw.isalnum() and data["password"] != data["postgres-password"]


def test_never_rewrites_existing_values():
    api = FakeCore(existing={"password": "a", "postgres-password": "b"})
    assert bootstrap.ensure_secret(api, "ns", "db", ["password", "postgres-password"]) == "unchanged"
    assert api.secrets["db"] == {"password": "a", "postgres-password": "b"}
    assert [c[0] for c in api.calls] == ["read"]


def test_adds_only_missing_keys():
    api = FakeCore(existing={"password": "a"})
    assert bootstrap.ensure_secret(api, "ns", "db", ["password", "postgres-password"]) == "patched"
    assert api.secrets["db"]["password"] == "a" and "postgres-password" in api.secrets["db"]


def test_concurrent_create_keeps_the_winner():
    api = FakeCore(race=True)
    assert bootstrap.ensure_secret(api, "ns", "db", ["password"]) == "unchanged"
    assert api.secrets["db"] == {"password": "theirs"}


def test_other_errors_propagate():
    class Forbidden(FakeCore):
        def read_namespaced_secret(self, name, ns):
            raise ApiException(status=403)

    with pytest.raises(ApiException):
        bootstrap.ensure_secret(Forbidden(), "ns", "db", ["password"])


def test_existing_secret_gains_keep_annotations_once():
    api = FakeCore(existing={"password": "a"})
    ann = {"helm.sh/resource-policy": "keep", "argocd.argoproj.io/sync-options": "Prune=false"}
    assert bootstrap.ensure_secret(api, "ns", "db", ["password"], annotations=ann) == "patched"
    assert api.annotations == ann and api.secrets["db"] == {"password": "a"}
    assert bootstrap.ensure_secret(api, "ns", "db", ["password"], annotations=ann) == "unchanged"
