"""Helm release discovery from `sh.helm.release.v1.*` Secrets (DESIGN §12).

Equivalent to provenance-collector-pack's `helm list --all` per namespace with the
Secrets driver: the latest revision of every release (any status). Release payload:
Secret `data.release` = base64(k8s) of base64(helm) of gzip(JSON) (gzip optional).

Requires cluster-wide `secrets` get/list (chart: `provenance.helmReleases.enabled`).
Optional chart update check against configured chart repositories
(`PROVENANCE_HELM_CHART_REPOS`: `https://…` index.yaml repos and/or `oci://…` prefixes).
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import yaml

from ..logs import get_logger
from .updates import DEFAULT_MAX_MAJOR_JUMP, UpdateInfo, compute_update, needs_tag_list

log = get_logger(__name__)

GZIP_MAGIC = b"\x1f\x8b\x08"
HELM_LABEL_SELECTOR = "owner=helm"


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
    try:
        raw = base64.b64decode(data, validate=False)
    except (ValueError, TypeError) as e:
        raise HelmDecodeError(f"invalid base64: {e}") from e
    if raw[:3] == GZIP_MAGIC:
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError) as e:
            raise HelmDecodeError(f"invalid gzip: {e}") from e
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
@dataclass
class ChartRepos:
    """Configured chart sources: classic repos (index.yaml) and OCI prefixes."""

    urls: list[str] = field(default_factory=list)
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None  # tests
    _index: dict[str, dict[str, list[str]]] = field(default_factory=dict, init=False)

    async def _load_index(self, http: httpx.AsyncClient, url: str) -> dict[str, list[str]]:
        if url in self._index:
            return self._index[url]
        versions: dict[str, list[str]] = {}
        try:
            resp = await http.get(url.rstrip("/") + "/index.yaml")
            if resp.status_code == 200:
                data = yaml.safe_load(resp.text) or {}
                for name, entries in (data.get("entries") or {}).items():
                    versions[name] = [str(e.get("version")) for e in entries or [] if e.get("version")]
        except (httpx.HTTPError, yaml.YAMLError) as e:
            log.warning("provenance.helm_repo_failed", repo=url, error=str(e)[:200])
        self._index[url] = versions
        return versions

    async def versions(self, chart: str, registry=None) -> tuple[list[str] | None, str | None]:
        """(available versions, source) for a chart name; first repo that knows it wins."""
        if not self.urls:
            return None, None
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, transport=self.transport) as http:
            for url in self.urls:
                if url.startswith("oci://"):
                    if registry is None:
                        continue
                    host, _, path = url[len("oci://"):].partition("/")
                    repo = f"{path.strip('/')}/{chart}".strip("/")
                    try:
                        tags = await registry.list_tags(host, repo)
                    except Exception as e:  # noqa: BLE001
                        log.debug("provenance.helm_oci_failed", repo=f"{host}/{repo}", error=str(e)[:200])
                        continue
                    if tags:
                        return [t.replace("_", "+") for t in tags], url
                else:
                    idx = await self._load_index(http, url)
                    if chart in idx:
                        return idx[chart], url
        return None, None


async def check_chart_updates(releases: list[HelmRelease], repos: ChartRepos, *, skip_prerelease: bool,
                              update_level: str, registry=None,
                              max_major_jump: int = DEFAULT_MAX_MAJOR_JUMP) -> None:
    """Fill `update` for releases whose chart is found in a configured repo. Like the
    images, `update` is only kept when an update is flagged (their omitempty usage)."""
    for rel in releases:
        if not needs_tag_list(rel.version):
            continue
        available, source = await repos.versions(rel.chart, registry)
        if available is None:
            continue
        info = compute_update(rel.version, available, skip_prerelease=skip_prerelease, update_level=update_level,
                              max_major_jump=max_major_jump)
        rel.chart_source = source
        rel.update = info if info.update_available else None
