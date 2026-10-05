"""Helm release discovery from `sh.helm.release.v1.*` Secrets (DESIGN §12).

Equivalent to provenance-collector-pack's `helm list --all` per namespace with the
Secrets driver: the latest revision of every release (any status). Release payload:
Secret `data.release` = base64(k8s) of base64(helm) of gzip(JSON) (gzip optional).

Requires cluster-wide `secrets` get/list (chart: `provenance.helmReleases.enabled`).
Optional chart update check against configured chart repositories
(`PROVENANCE_HELM_CHART_REPOS`: `https://…` index.yaml repos and/or `oci://…` prefixes), with repo
indexes / OCI tag lists and per-release results cached under `CACHE_DIR/helm-index/`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from typing import Any

import httpx
import yaml

from ..logs import get_logger
from .updates import DEFAULT_MAX_MAJOR_JUMP, UpdateInfo, compute_update, needs_tag_list

log = get_logger(__name__)

GZIP_MAGIC = b"\x1f\x8b\x08"
HELM_LABEL_SELECTOR = "owner=helm"
# security review M1: anyone who can create an `owner=helm` Secret could plant a gzip bomb.
# Decompressed release payloads above this are refused (PROVENANCE_HELM_MAX_RELEASE_BYTES).
MAX_RELEASE_BYTES = int(os.environ.get("PROVENANCE_HELM_MAX_RELEASE_BYTES") or 16 * 1024 * 1024)
MAX_SECRET_PAYLOAD_BYTES = 2 * 1024 * 1024  # Kubernetes caps Secrets at 1 MiB; base64 adds a third
MAX_INDEX_BYTES = 64 * 1024 * 1024  # chart repo index.yaml


def gunzip_capped(raw: bytes, limit: int | None = None) -> bytes:
    """gzip.decompress with an output cap; raises HelmDecodeError past it."""
    limit = MAX_RELEASE_BYTES if limit is None else limit
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(raw, limit + 1)
    except zlib.error as e:
        raise HelmDecodeError(f"invalid gzip: {e}") from e
    if len(out) > limit or d.unconsumed_tail:
        raise HelmDecodeError(f"release payload larger than {limit} bytes after decompression")
    if not d.eof:
        raise HelmDecodeError("invalid gzip: truncated stream")
    return out


@dataclass
class HelmRelease:
    release_name: str
    namespace: str
    chart: str
    version: str
    app_version: str
    status: str
    revision: int = 0
    last_deployed: str | None = None
    update: UpdateInfo | None = None
    chart_source: str | None = None  # repo the update was resolved against (ours)
    update_check: str | None = None  # CHECK_* below; None = no chart update check ran

    def as_json(self) -> dict[str, Any]:
        """Their HelmRecord (update omitempty)."""
        out: dict[str, Any] = {"releaseName": self.release_name, "namespace": self.namespace, "chart": self.chart,
                               "version": self.version, "appVersion": self.app_version, "status": self.status}
        if self.update is not None:
            out["update"] = self.update.as_json()
        return out


class HelmDecodeError(ValueError):
    pass


def decode_release_payload(data: str | bytes) -> dict[str, Any]:
    """Decode the helm payload (the value AFTER Kubernetes' own base64 is removed)."""
    if isinstance(data, str):
        data = data.encode()
    if len(data) > MAX_SECRET_PAYLOAD_BYTES:
        raise HelmDecodeError("release payload too large")
    try:
        raw = base64.b64decode(data, validate=False)
    except (ValueError, TypeError) as e:
        raise HelmDecodeError(f"invalid base64: {e}") from e
    if raw[:3] == GZIP_MAGIC:
        raw = gunzip_capped(raw)
    elif len(raw) > MAX_RELEASE_BYTES:
        raise HelmDecodeError(f"release payload larger than {MAX_RELEASE_BYTES} bytes")
    try:
        obj = json.loads(raw)
    except ValueError as e:
        raise HelmDecodeError(f"invalid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise HelmDecodeError("release payload is not an object")
    return obj


def decode_secret(secret: dict[str, Any]) -> dict[str, Any]:
    """Decode a Secret as returned by the API (`data.release` is Kubernetes-base64)."""
    payload = ((secret.get("data") or {}).get("release")) or ""
    if not payload:
        raise HelmDecodeError("secret has no data.release")
    if len(payload) > 2 * MAX_SECRET_PAYLOAD_BYTES:
        raise HelmDecodeError("secret data.release too large")
    try:
        inner = base64.b64decode(payload)
    except (ValueError, TypeError) as e:
        raise HelmDecodeError(f"invalid secret base64: {e}") from e
    return decode_release_payload(inner)


def release_from_payload(rel: dict[str, Any], fallback_ns: str = "") -> HelmRelease:
    meta = ((rel.get("chart") or {}).get("metadata")) or {}
    info = rel.get("info") or {}
    return HelmRelease(
        release_name=rel.get("name") or "",
        namespace=rel.get("namespace") or fallback_ns,
        chart=meta.get("name") or "",
        version=meta.get("version") or "",
        app_version=meta.get("appVersion") or "",
        status=info.get("status") or "unknown",
        revision=int(rel.get("version") or 0),
        last_deployed=info.get("last_deployed"),
    )


def _revision(secret: dict[str, Any]) -> int:
    labels = (secret.get("metadata") or {}).get("labels") or {}
    try:
        return int(labels.get("version") or 0)
    except ValueError:
        return 0


def latest_release_secrets(secrets: list[dict[str, Any]], excluded: set[str] | None = None) -> list[dict[str, Any]]:
    """Helm `filterLatestReleases`: highest revision per (namespace, release name),
    using the driver labels so only the winners get decoded."""
    excluded = excluded or set()
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for s in secrets:
        meta = s.get("metadata") or {}
        labels = meta.get("labels") or {}
        if labels.get("owner") != "helm" or s.get("type", "helm.sh/release.v1") != "helm.sh/release.v1":
            continue
        ns = meta.get("namespace") or ""
        if ns in excluded:
            continue
        name = labels.get("name") or (meta.get("name") or "").removeprefix("sh.helm.release.v1.").rsplit(".v", 1)[0]
        key = (ns, name)
        if key not in best or _revision(s) > _revision(best[key]):
            best[key] = s
    return [best[k] for k in sorted(best)]


def releases_from_secrets(secrets: list[dict[str, Any]], excluded: set[str] | None = None) -> tuple[list[HelmRelease], list[str]]:
    out: list[HelmRelease] = []
    errors: list[str] = []
    for s in latest_release_secrets(secrets, excluded):
        meta = s.get("metadata") or {}
        try:
            rel = release_from_payload(decode_secret(s), meta.get("namespace") or "")
        except HelmDecodeError as e:
            errors.append(f"{meta.get('namespace')}/{meta.get('name')}: {e}")
            continue
        out.append(rel)
    return out, errors


def list_helm_secrets_sync() -> list[dict[str, Any]]:
    """All helm release Secrets cluster-wide (needs secrets list RBAC)."""
    from kubernetes import client

    from ..inventory import _list_all, _load_kube_config

    _load_kube_config()
    core = client.CoreV1Api()
    return _list_all(core.list_secret_for_all_namespaces, label_selector=HELM_LABEL_SELECTOR)


async def discover(excluded_namespaces: list[str] | None = None) -> tuple[list[HelmRelease], list[str]]:
    secrets = await asyncio.to_thread(list_helm_secrets_sync)
    return releases_from_secrets(secrets, set(excluded_namespaces or []))


# ---------------------------------------------------------------- chart update check
DOCKER_HUB_HOSTS = ("docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com")
DEFAULT_INDEX_TTL_HOURS = 12.0

# `HelmRelease.update_check` values
CHECK_DONE = "checked"  # found in a configured source; `update` set when one is flagged
CHECK_NOT_CONFIGURED = "not-configured"  # no configured source publishes the chart
CHECK_ERROR = "error"  # a source that might publish it failed (not carried; retried next scan)
CHECK_SKIPPED = "skipped"  # version is not semver-like (no tag list needed)


def _utcnow() -> float:
    return time.time()


class HelmIndexCache:
    """On-disk cache under `CACHE_DIR/helm-index/` (grace, 2026-10-05: the stage re-downloaded every
    configured `index.yaml` and OCI tag list on every scan).

    * `index-<h>.json`: parsed chart -> versions of one index.yaml repo + its ETag / Last-Modified.
      Fresh for `ttl_hours`; after that it is revalidated (If-None-Match / If-Modified-Since when the
      server sent validators; a 304 only refreshes `fetchedAt`). A failed refresh falls back to the
      stale copy.
    * `oci-<h>.json`: an OCI tag list (an empty list = repository not found), same TTL; errors are
      not cached.
    * `checks.json`: the last update-check result per release (see `check_chart_updates`).

    `root=None` (or an unwritable directory) keeps everything in memory for this process.
    """

    def __init__(self, root: str | None, ttl_hours: float = DEFAULT_INDEX_TTL_HOURS):
        self.root = root
        self.ttl = max(0.0, float(ttl_hours)) * 3600
        self._mem: dict[str, dict[str, Any]] = {}
        if root:
            try:
                os.makedirs(root, exist_ok=True)
            except OSError as e:
                log.warning("provenance.helm_cache_unavailable", dir=root, error=str(e)[:200])
                self.root = None

    @staticmethod
    def _name(kind: str, key: str) -> str:
        return f"{kind}-{hashlib.sha256(key.encode()).hexdigest()[:24]}.json"

    def get(self, name: str) -> dict[str, Any] | None:
        if name in self._mem:
            return self._mem[name]
        if not self.root:
            return None
        try:
            with open(os.path.join(self.root, name), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        self._mem[name] = data
        return data

    def put(self, name: str, data: dict[str, Any]) -> None:
        self._mem[name] = data
        if not self.root:
            return
        try:
            fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".tmp-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, separators=(",", ":"))
            os.replace(tmp, os.path.join(self.root, name))
        except OSError as e:
            log.warning("provenance.helm_cache_write_failed", file=name, error=str(e)[:200])

    def fresh(self, entry: dict[str, Any] | None) -> bool:
        return (entry is not None and self.ttl > 0
                and _utcnow() - float(entry.get("fetchedAt") or 0) < self.ttl)

    def index_name(self, url: str) -> str:
        return self._name("index", url)

    def oci_name(self, host: str, repo: str) -> str:
        return self._name("oci", f"{host}/{repo}")


_YamlLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def parse_index(body: bytes) -> dict[str, list[str]]:
    """chart -> versions of an index.yaml. libyaml when available: the pure-Python loader needs ~18 s
    (on a desktop CPU) for prometheus-community's 6.5 MB index, libyaml ~5.5 s. Runs in a thread."""
    data = yaml.load(body, Loader=_YamlLoader) or {}  # noqa: S506 (a safe loader)
    versions: dict[str, list[str]] = {}
    for chart, entries in ((data.get("entries") or {}) if isinstance(data, dict) else {}).items():
        versions[str(chart)] = [str(e.get("version")) for e in entries or []
                                if isinstance(e, dict) and e.get("version")]
    return versions


@dataclass
class ChartLookup:
    versions: list[str] | None
    source: str | None
    status: str  # CHECK_DONE | CHECK_NOT_CONFIGURED | CHECK_ERROR


@dataclass
class ChartRepos:
    """Configured chart sources: classic repos (index.yaml) and OCI prefixes.

    `oci://host/path` is a prefix (`host/path/<chart>`), or the chart itself when the last path
    segment is the chart name. Docker Hub OCI entries are only used in the second form: a prefix on
    Docker Hub would turn every chart no other source publishes into a rate-limited tag-list probe.
    """

    urls: list[str] = field(default_factory=list)
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None  # tests
    cache: HelmIndexCache | None = None
    _index: dict[str, tuple[dict[str, list[str]], bool]] = field(default_factory=dict, init=False)
    _oci: dict[tuple[str, str], list[str] | None] = field(default_factory=dict, init=False)
    _http: httpx.AsyncClient | None = field(default=None, init=False)
    requests: int = field(default=0, init=False)  # network round trips (index GETs + tag lists)

    def __post_init__(self) -> None:
        if self.cache is None:
            self.cache = HelmIndexCache(None)

    def fingerprint(self) -> str:
        return ",".join(self.urls)

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, transport=self.transport)
        return self._http

    async def _load_index(self, url: str) -> tuple[dict[str, list[str]], bool]:
        """(chart -> versions, ok). ok=False: no usable copy (fetch failed, nothing cached)."""
        if url in self._index:
            return self._index[url]
        assert self.cache is not None
        name = self.cache.index_name(url)
        entry = self.cache.get(name)
        if entry is not None and entry.get("url") == url and self.cache.fresh(entry):
            self._index[url] = (entry.get("versions") or {}), True
            return self._index[url]
        if entry is not None and entry.get("url") != url:
            entry = None
        headers: dict[str, str] = {}
        if entry is not None:
            if entry.get("etag"):
                headers["If-None-Match"] = entry["etag"]
            if entry.get("lastModified"):
                headers["If-Modified-Since"] = entry["lastModified"]
        result: tuple[dict[str, list[str]], bool]
        try:
            body = b""
            self.requests += 1
            async with self._client().stream("GET", url.rstrip("/") + "/index.yaml", headers=headers) as resp:
                status = resp.status_code
                etag, last_mod = resp.headers.get("etag"), resp.headers.get("last-modified")
                if status == 200:
                    buf = bytearray()
                    async for chunk in resp.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > MAX_INDEX_BYTES:
                            raise httpx.HTTPError(f"index.yaml larger than {MAX_INDEX_BYTES} bytes")
                    body = bytes(buf)
            if status == 304 and entry is not None:
                entry = {**entry, "fetchedAt": _utcnow()}
                self.cache.put(name, entry)
                result = (entry.get("versions") or {}), True
            elif status == 200:
                t = time.monotonic()
                versions = await asyncio.to_thread(parse_index, body)
                log.info("provenance.helm_index_parsed", repo=url, bytes=len(body), charts=len(versions),
                         ms=int((time.monotonic() - t) * 1000))
                self.cache.put(name, {"url": url, "fetchedAt": _utcnow(), "etag": etag, "lastModified": last_mod,
                                      "versions": versions})
                result = versions, True
            else:
                raise httpx.HTTPError(f"GET index.yaml -> {status}")
        except (httpx.HTTPError, yaml.YAMLError) as e:
            log.warning("provenance.helm_repo_failed", repo=url, error=str(e)[:200], stale=entry is not None)
            result = ((entry.get("versions") or {}), True) if entry is not None else ({}, False)
        self._index[url] = result
        return result

    async def _oci_tags(self, registry, host: str, repo: str) -> list[str] | None:
        """Tag list ([] = not found) or None on error. Disk-cached for the TTL."""
        key = (host, repo)
        if key in self._oci:
            return self._oci[key]
        assert self.cache is not None
        name = self.cache.oci_name(host, repo)
        entry = self.cache.get(name)
        if entry is not None and entry.get("ref") == f"{host}/{repo}" and self.cache.fresh(entry):
            self._oci[key] = list(entry.get("tags") or [])
            return self._oci[key]
        try:
            self.requests += 1
            tags: list[str] | None = list(await registry.list_tags(host, repo) or [])
            self.cache.put(name, {"ref": f"{host}/{repo}", "fetchedAt": _utcnow(), "tags": tags})
        except Exception as e:  # noqa: BLE001
            log.debug("provenance.helm_oci_failed", repo=f"{host}/{repo}", error=str(e)[:200])
            tags = list(entry.get("tags") or []) if entry is not None and entry.get("ref") == f"{host}/{repo}" else None
        self._oci[key] = tags
        return tags

    @staticmethod
    def oci_candidate(url: str, chart: str) -> tuple[str, str] | None:
        """(host, repository) to list for `chart` under an `oci://` entry, or None (not probed)."""
        host, _, path = url[len("oci://"):].partition("/")
        path = path.strip("/")
        if path and path.rsplit("/", 1)[-1] == chart:
            return host, path
        if host.lower() in DOCKER_HUB_HOSTS:
            return None
        return host, f"{path}/{chart}".strip("/")

    async def lookup(self, chart: str, registry=None) -> ChartLookup:
        """First configured source that publishes the chart wins."""
        errored = False
        for url in self.urls:
            if url.startswith("oci://"):
                cand = self.oci_candidate(url, chart)
                if registry is None or cand is None:
                    continue
                tags = await self._oci_tags(registry, *cand)
                if tags is None:
                    errored = True
                elif tags:
                    return ChartLookup([t.replace("_", "+") for t in tags], url, CHECK_DONE)
            else:
                idx, ok = await self._load_index(url)
                errored = errored or not ok
                if chart in idx:
                    return ChartLookup(idx[chart], url, CHECK_DONE)
        return ChartLookup(None, None, CHECK_ERROR if errored else CHECK_NOT_CONFIGURED)

    async def versions(self, chart: str, registry=None) -> tuple[list[str] | None, str | None]:
        """(available versions, source) for a chart name; first repo that knows it wins."""
        if not self.urls:
            return None, None
        try:
            r = await self.lookup(chart, registry)
        finally:
            await self.aclose()
        return r.versions, r.source


CHECKS_FILE = "checks.json"


async def check_chart_updates(releases: list[HelmRelease], repos: ChartRepos, *, skip_prerelease: bool,
                              update_level: str, registry=None,
                              max_major_jump: int = DEFAULT_MAX_MAJOR_JUMP,
                              max_age_hours: float | None = None, force: bool = False) -> dict[str, int]:
    """Fill `update` for releases whose chart is found in a configured repo. Like the
    images, `update` is only kept when an update is flagged (their omitempty usage).

    With `max_age_hours` (the stage passes `rescanAfterHours`), a release whose chart and version
    are unchanged since its last check, checked under the same configuration less than that long
    ago, *carries* the stored result (`repos.cache` `checks.json`) without any request; errors are
    never carried. Returns counts: checked / carried / notConfigured / errors / skipped.
    """
    assert repos.cache is not None
    cfg = json.dumps([repos.fingerprint(), skip_prerelease, update_level, max_major_jump])
    stored = repos.cache.get(CHECKS_FILE) or {}
    prev_checks: dict[str, Any] = (stored.get("releases") or {}) if stored.get("config") == cfg else {}
    checks: dict[str, Any] = {}
    stats = {"checked": 0, "carried": 0, "notConfigured": 0, "errors": 0, "skipped": 0}
    now_ts = _utcnow()
    try:
        for rel in releases:
            key = f"{rel.namespace}/{rel.release_name}"
            if not needs_tag_list(rel.version):
                rel.update_check = CHECK_SKIPPED
                stats["skipped"] += 1
                continue
            prev = prev_checks.get(key)
            if (not force and max_age_hours is not None and isinstance(prev, dict)
                    and prev.get("chart") == rel.chart and prev.get("version") == rel.version
                    and prev.get("updateCheck") in (CHECK_DONE, CHECK_NOT_CONFIGURED)
                    and now_ts - float(prev.get("checkedAt") or 0) < max_age_hours * 3600):
                rel.update = UpdateInfo.from_json(prev.get("update"))
                rel.chart_source = prev.get("source")
                rel.update_check = prev["updateCheck"]
                checks[key] = prev
                stats["carried"] += 1
                continue
            found = await repos.lookup(rel.chart, registry)
            rel.update_check = found.status
            if found.versions is not None:
                info = compute_update(rel.version, found.versions, skip_prerelease=skip_prerelease,
                                      update_level=update_level, max_major_jump=max_major_jump)
                rel.chart_source = found.source
                rel.update = info if info.update_available else None
                stats["checked"] += 1
            elif found.status == CHECK_ERROR:
                stats["errors"] += 1
            else:
                stats["notConfigured"] += 1
            if found.status != CHECK_ERROR:
                checks[key] = {"chart": rel.chart, "version": rel.version, "checkedAt": now_ts,
                               "updateCheck": found.status, "source": rel.chart_source,
                               "update": rel.update.as_json() if rel.update else None}
    finally:
        await repos.aclose()
    if checks != prev_checks or stored.get("config") != cfg:
        repos.cache.put(CHECKS_FILE, {"config": cfg, "releases": checks})
    return stats
