"""CISA KEV catalog (compliance review S2): vendored snapshot, daily refresh into CACHE_DIR."""

import json
import time
from pathlib import Path

import httpx

from posture.reports import kev

FIX = Path(__file__).parent / "fixtures" / "kev_small.json"


def test_snapshot_is_vendored_and_trimmed():
    cat = kev._load_file(kev.SNAPSHOT)
    assert cat and len(cat["entries"]) > 1000 and cat["version"]
    added, due, ransomware = next(iter(cat["entries"].values()))
    assert len(due) == 10 and ransomware in (0, 1)


def test_refresh_into_the_cache_and_lookup(tmp_path, monkeypatch):
    def fake_get(url, timeout, follow_redirects):
        assert url == "https://kev.example/feed.json"
        return httpx.Response(200, json=json.loads(FIX.read_text()), request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    path = tmp_path / "kev" / "known_exploited_vulnerabilities.json"
    assert kev.refresh("https://kev.example/feed.json", path)
    monkeypatch.setattr(kev, "cache_path", lambda: path)
    kev.set_catalog(None)
    try:
        cat = kev.catalog(allow_refresh=False, now=time.time())
        assert cat["version"] == "2026.01.01" and cat["source"] == str(path)
        e = kev.lookup("cve-2021-44228")
        assert e and e.due.isoformat() == "2021-12-24" and e.ransomware
        assert kev.lookup("CVE-2099-0001") is None
    finally:
        kev.set_catalog(None)


def test_offline_falls_back_to_the_snapshot(tmp_path, monkeypatch):
    def offline(*a, **k):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "get", offline)
    assert kev.refresh("https://kev.example/feed.json", tmp_path / "k.json") is False
    monkeypatch.setattr(kev, "cache_path", lambda: tmp_path / "missing" / "k.json")
    monkeypatch.setenv("KEV_REFRESH", "true")
    kev.set_catalog(None)
    try:
        assert kev.catalog()["source"].endswith("kev_snapshot.json")
    finally:
        kev.set_catalog(None)
