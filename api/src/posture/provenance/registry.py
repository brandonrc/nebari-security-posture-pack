"""Minimal async OCI distribution client for the provenance checks (DESIGN §12).

Only what the checks need: manifests (GET/HEAD), blobs (small, capped), tag
listing (paginated) and the OCI 1.1 referrers API. Anonymous bearer-token auth
via `WWW-Authenticate`, optional basic credentials from a docker config.json
(`REGISTRY_AUTH_FILE` / `DOCKER_CONFIG`). Plain http for registries listed as
insecure (the in-cluster mirror and `MIRROR_REWRITE` targets).

Everything network-facing sits behind the `Registry` protocol so tests can use
an in-memory fake (see tests/provenance/fakes.py).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from ..logs import get_logger

log = get_logger(__name__)

MT_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MT_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
MT_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
ACCEPT = ", ".join([MT_OCI_INDEX, MT_OCI_MANIFEST, MT_DOCKER_LIST, MT_DOCKER_MANIFEST])
INDEX_TYPES = (MT_OCI_INDEX, MT_DOCKER_LIST)

DOCKER_HUB_API = "registry-1.docker.io"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TAG_PAGES = 50


@dataclass
class Manifest:
    media_type: str
    digest: str | None
    body: dict[str, Any]

    @property
    def is_index(self) -> bool:
        mt = self.media_type or self.body.get("mediaType") or ""
        return mt in INDEX_TYPES or ("manifests" in self.body and "layers" not in self.body)

    @property
    def manifests(self) -> list[dict[str, Any]]:
        return list(self.body.get("manifests") or [])

    @property
    def layers(self) -> list[dict[str, Any]]:
        return list(self.body.get("layers") or [])


class RegistryError(Exception):
    """Registry unreachable / auth failure / unexpected status (not "not found")."""


class Registry(Protocol):
    async def get_manifest(self, registry: str, repository: str, reference: str) -> Manifest | None: ...

    async def manifest_exists(self, registry: str, repository: str, reference: str) -> bool: ...

    async def get_blob(self, registry: str, repository: str, digest: str, max_bytes: int = ...) -> bytes | None: ...

    async def list_tags(self, registry: str, repository: str) -> list[str]: ...

    async def referrers(self, registry: str, repository: str, digest: str) -> list[dict[str, Any]] | None: ...


def api_host(registry: str) -> str:
    return DOCKER_HUB_API if registry in ("docker.io", "index.docker.io") else registry


def load_docker_auths(path: str | None) -> dict[str, tuple[str, str]]:
    """{registry host: (user, password)} from a docker config.json (`auths`)."""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    out: dict[str, tuple[str, str]] = {}
    for host, entry in (data.get("auths") or {}).items():
        host = re.sub(r"^https?://", "", host).split("/", 1)[0]
        if host in ("index.docker.io", "registry-1.docker.io"):
            host = "docker.io"
        user, pw = entry.get("username"), entry.get("password")
        if (not user or not pw) and entry.get("auth"):
            try:
                user, _, pw = base64.b64decode(entry["auth"]).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                continue
        if user and pw:
            out[host] = (user, pw)
    return out


_CHALLENGE_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_challenge(header: str) -> tuple[str, dict[str, str]]:
    scheme, _, rest = header.strip().partition(" ")
    return scheme.lower(), dict(_CHALLENGE_RE.findall(rest))


def _fmt(registry: str, repository: str, reference: str) -> str:
    return f"{registry}/{repository}{'@' if ':' in reference and reference.startswith('sha256') else ':'}{reference}"


def _status(resp: httpx.Response) -> str:
    if resp.status_code == 429:
        return "429 rate limited (configure registry credentials, e.g. REGISTRY_AUTH_FILE)"
    return str(resp.status_code)


def _next_link(link: str | None) -> str | None:
    if not link:
        return None
    m = re.search(r"<([^>]+)>\s*;\s*rel=\"?next\"?", link)
    return m.group(1) if m else None


@dataclass
class HttpRegistry:
    """httpx implementation of `Registry`."""

    insecure_hosts: set[str] = field(default_factory=set)
    rewrite: dict[str, str] = field(default_factory=dict)
    auths: dict[str, tuple[str, str]] = field(default_factory=dict)
    timeout: float = 30.0
    max_concurrency: int = 8
    _tokens: dict[tuple[str, str], str] = field(default_factory=dict, init=False, repr=False)
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)
    _sem: asyncio.Semaphore | None = field(default=None, init=False, repr=False)

    async def __aenter__(self) -> HttpRegistry:
        self._ensure()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True,
                                             headers={"User-Agent": "nebari-security-posture/provenance"})
            self._sem = asyncio.Semaphore(self.max_concurrency)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _base(self, registry: str) -> str:
        host = self.rewrite.get(registry, registry)
        scheme = "http" if host in self.insecure_hosts else "https"
        return f"{scheme}://{api_host(host)}"

    async def _token(self, registry: str, challenge: str, scope: str) -> str | None:
        scheme, params = parse_challenge(challenge)
        creds = self.auths.get(registry)
        if scheme == "basic":
            return None
        realm = params.get("realm")
        if not realm:
            return None
        query = {k: v for k, v in (("service", params.get("service")), ("scope", scope)) if v}
        client = self._ensure()
        auth = httpx.BasicAuth(*creds) if creds else None
        resp = await client.get(realm, params=query, auth=auth)
        if resp.status_code != 200:
            raise RegistryError(f"token endpoint {realm} returned {resp.status_code}")
        data = resp.json()
        return data.get("token") or data.get("access_token")

    async def _request(self, method: str, registry: str, repository: str, path: str,
                       headers: dict[str, str] | None = None, url: str | None = None) -> httpx.Response:
        client = self._ensure()
        assert self._sem is not None
        scope = f"repository:{repository}:pull"
        key = (registry, scope)
        full = url or f"{self._base(registry)}/v2/{repository}/{path}"
        hdrs = dict(headers or {})
        async with self._sem:
            for _attempt in range(2):
                req_headers = dict(hdrs)
                tok = self._tokens.get(key)
                if tok:
                    req_headers["Authorization"] = f"Bearer {tok}"
                try:
                    resp = await client.request(method, full, headers=req_headers)
                except httpx.HTTPError as e:
                    raise RegistryError(f"{registry}: {type(e).__name__}: {e}") from e
                if resp.status_code != 401:
                    return resp
                challenge = resp.headers.get("www-authenticate", "")
                scheme, _ = parse_challenge(challenge)
                if scheme == "basic" and registry in self.auths:
                    user, pw = self.auths[registry]
                    hdrs["Authorization"] = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
                    continue
                try:
                    tok = await self._token(registry, challenge, scope)
                except httpx.HTTPError as e:
                    raise RegistryError(f"{registry}: token request failed: {e}") from e
                if not tok:
                    return resp
                self._tokens[key] = tok
            return resp

    async def get_manifest(self, registry: str, repository: str, reference: str) -> Manifest | None:
        resp = await self._request("GET", registry, repository, f"manifests/{reference}", {"Accept": ACCEPT})
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise RegistryError(f"GET manifest {_fmt(registry, repository, reference)} -> {_status(resp)}")
        raw = resp.content[:MAX_MANIFEST_BYTES]
        try:
            body = json.loads(raw)
        except ValueError as e:
            raise RegistryError(f"invalid manifest JSON for {registry}/{repository}:{reference}") from e
        digest = resp.headers.get("docker-content-digest") or "sha256:" + hashlib.sha256(resp.content).hexdigest()
        mt = (resp.headers.get("content-type") or "").split(";")[0].strip() or body.get("mediaType") or ""
        return Manifest(mt, digest, body if isinstance(body, dict) else {})

    async def manifest_exists(self, registry: str, repository: str, reference: str) -> bool:
        resp = await self._request("HEAD", registry, repository, f"manifests/{reference}", {"Accept": ACCEPT})
        if resp.status_code == 200:
            return True
        if resp.status_code in (404, 400):  # some registries answer 400 MANIFEST_INVALID / NAME_UNKNOWN
            return False
        raise RegistryError(f"HEAD manifest {_fmt(registry, repository, reference)} -> {_status(resp)}")

    async def get_blob(self, registry: str, repository: str, digest: str, max_bytes: int = 2 * 1024 * 1024) -> bytes | None:
        resp = await self._request("GET", registry, repository, f"blobs/{digest}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise RegistryError(f"GET blob {registry}/{repository}@{digest} -> {resp.status_code}")
        return resp.content[:max_bytes]

    async def list_tags(self, registry: str, repository: str) -> list[str]:
        tags: list[str] = []
        url: str | None = f"{self._base(registry)}/v2/{repository}/tags/list?n=1000"
        for _ in range(MAX_TAG_PAGES):
            if url is None:
                break
            resp = await self._request("GET", registry, repository, "", url=url)
            if resp.status_code == 404:
                return tags
            if resp.status_code != 200:
                raise RegistryError(f"list tags {registry}/{repository} -> {_status(resp)}")
            tags.extend((resp.json() or {}).get("tags") or [])
            nxt = _next_link(resp.headers.get("link"))
            url = None if not nxt else (nxt if nxt.startswith("http") else self._base(registry) + nxt)
        return tags

    async def referrers(self, registry: str, repository: str, digest: str) -> list[dict[str, Any]] | None:
        """OCI 1.1 referrers API. None when the registry does not support it."""
        resp = await self._request("GET", registry, repository, f"referrers/{digest}", {"Accept": MT_OCI_INDEX})
        if resp.status_code != 200:
            return None
        ct = (resp.headers.get("content-type") or "").split(";")[0].strip()
        if ct and ct != MT_OCI_INDEX and "json" not in ct:
            return None
        try:
            return list((resp.json() or {}).get("manifests") or [])
        except ValueError:
            return None
