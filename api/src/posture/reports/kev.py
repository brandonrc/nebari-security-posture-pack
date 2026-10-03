"""CISA Known Exploited Vulnerabilities (KEV) catalog lookup (compliance review S2 / S4).

KEV due dates (CISA BOD 22-01 and successors) override severity SLAs for federal civilian
systems, and a KEV finding is never down-weighted in the hygiene index.

Source order:
1. `<CACHE_DIR>/kev/known_exploited_vulnerabilities.json`, refreshed from `KEV_URL` (default the
   CISA feed) at most once a day by whichever process reads it first: the worker (control evidence
   run, auto-generated reports) and the API (report generation, /summary). The download is
   bounded by a short timeout and never fails a caller.
2. the vendored snapshot `data/kev_snapshot.json` (trimmed to CVE -> dateAdded, dueDate, ransomware).
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

SNAPSHOT = Path(__file__).parent / "data" / "kev_snapshot.json"
DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_SECONDS = 24 * 3600
_lock = threading.Lock()
_state: dict[str, Any] = {"loaded_at": 0.0, "catalog": None, "path": None}


@dataclass(frozen=True)
class KevEntry:
    cve: str
    date_added: date | None
    due: date | None
    ransomware: bool


def _parse_full(doc: dict[str, Any]) -> dict[str, tuple[str, str, int]]:
    out = {}
    for v in doc.get("vulnerabilities") or []:
        if isinstance(v, dict) and v.get("cveID"):
            out[v["cveID"]] = (v.get("dateAdded") or "", v.get("dueDate") or "",
                               1 if v.get("knownRansomwareCampaignUse") == "Known" else 0)
    return out


def _load_file(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    vulns = doc.get("vulnerabilities")
    if isinstance(vulns, dict):  # trimmed snapshot
        entries = {k: tuple(v) for k, v in vulns.items()}
    else:
        entries = _parse_full(doc)
    return {"version": doc.get("catalogVersion"), "released": doc.get("dateReleased"), "entries": entries,
            "source": str(path)}


def cache_path() -> Path | None:
    try:
        from ..config import get_settings

        base = get_settings().cache_dir
    except Exception:  # noqa: BLE001
        base = os.environ.get("CACHE_DIR")
    return Path(base) / "kev" / "known_exploited_vulnerabilities.json" if base else None


def refresh(url: str | None = None, path: Path | None = None, timeout: float = 10) -> bool:
    """Download the KEV feed into the cache (atomic). Returns True on success; never raises."""
    url = url or os.environ.get("KEV_URL") or DEFAULT_URL
    path = path or cache_path()
    if not url or path is None or url.lower() in ("off", "none", "disabled"):
        return False
    try:
        import httpx

        r = httpx.get(url, timeout=timeout, follow_redirects=True)
        r.raise_for_status()
        doc = r.json()
        if not isinstance(doc.get("vulnerabilities"), list):
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        os.replace(tmp, path)
        return True
    except Exception:  # noqa: BLE001  (offline / air-gapped: the snapshot is used)
        return False


def catalog(*, allow_refresh: bool = True, now: float | None = None) -> dict[str, Any]:
    """{version, released, entries: {CVE: (dateAdded, dueDate, ransomware)}, source}."""
    now = now or time.time()
    with _lock:
        if _state["catalog"] is not None and now - _state["loaded_at"] < 3600:
            return _state["catalog"]
        path = cache_path()
        fresh = path is not None and path.exists() and now - path.stat().st_mtime < REFRESH_SECONDS
        if path is not None and not fresh and allow_refresh and os.environ.get("KEV_REFRESH", "true") != "false":
            fresh = refresh(path=path)
        cat = (_load_file(path) if path is not None and path.exists() else None) or _load_file(SNAPSHOT) or {
            "version": None, "released": None, "entries": {}, "source": "none"}
        _state.update(catalog=cat, loaded_at=now)
        return cat


def set_catalog(cat: dict[str, Any] | None) -> None:
    """Test hook: pin the catalog (None = reload)."""
    with _lock:
        _state.update(catalog=cat, loaded_at=time.time() if cat is not None else 0.0)


def lookup(vuln_id: str) -> KevEntry | None:
    e = (catalog().get("entries") or {}).get((vuln_id or "").upper())
    if not e:
        return None

    def d(s: str) -> date | None:
        try:
            return date.fromisoformat(s[:10]) if s else None
        except ValueError:
            return None

    return KevEntry(vuln_id.upper(), d(e[0]), d(e[1]), bool(e[2]))
