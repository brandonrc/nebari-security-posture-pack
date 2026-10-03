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
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

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
# security review H3: every body is streamed and capped (decoded bytes, so gzip cannot inflate past it)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TAG_LIST_BYTES = 8 * 1024 * 1024  # all pages together
MAX_ATTESTATION_BYTES = 16 * 1024 * 1024  # upper bound for get_blob
MAX_TOKEN_BYTES = 1024 * 1024
MAX_ERROR_BODY_BYTES = 64 * 1024
MAX_TAG_PAGES = 50
MAX_REDIRECTS = 5
# Token realms on a host other than the registry (or its parent domain) must be listed here
# (PROVENANCE_REGISTRY_AUTH_REALMS, comma list of hosts; added to this default).
DEFAULT_REALM_HOSTS = ("auth.docker.io",)


class BodyTooLarge(Exception):
    pass


def _env_hosts(name: str) -> set[str]:
    return {h.strip().lower() for h in os.environ.get(name, "").split(",") if h.strip()}


def _blocked_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
            or a.is_unspecified)


def _parent_domain(host: str) -> str | None:
    host = host.split(":", 1)[0].lower()
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None
    except ValueError:
        pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else None


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
    realm_hosts: set[str] = field(default_factory=lambda: {*DEFAULT_REALM_HOSTS,
                                                           *_env_hosts("PROVENANCE_REGISTRY_AUTH_REALMS")})
    resolver: Any = None  # async (host) -> list[str] of IPs; tests substitute it
    transport: httpx.AsyncBaseTransport | None = None  # tests
    _dns: dict[str, tuple[float, list[str]]] = field(default_factory=dict, init=False, repr=False)
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
            # redirects are followed by hand (`_send`) so every hop is checked
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=min(10.0, self.timeout)),
                                             follow_redirects=False, transport=self.transport,
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

    # ------------------------------------------------------------------ SSRF guards (security H3)
    def _trusted_host(self, host: str) -> bool:
        """Hosts that may resolve to private addresses: the in-cluster mirror / rewrite targets."""
        return host in self.insecure_hosts or host.split(":", 1)[0] in {h.split(":", 1)[0] for h in self.insecure_hosts}

    async def _resolve(self, host: str) -> list[str]:
        if self.resolver is not None:
            return list(await self.resolver(host))
        name = host.strip("[]")
        try:
            ipaddress.ip_address(name)
            return [name]
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        hit = self._dns.get(name)
        if hit and loop.time() - hit[0] < 60:
            return hit[1]
        infos = await loop.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        ips = [i[4][0] for i in infos]
        self._dns[name] = (loop.time(), ips)
        return ips

    async def _check_target(self, url: str, origin_host: str) -> None:
        """Redirect / realm targets: never private, loopback or link-local addresses unless the
        host is a configured insecure (in-cluster) registry, and only http(s)."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RegistryError(f"refusing URL {url[:120]!r}")
        host = parts.netloc.rsplit("@", 1)[-1].lower()
        if parts.scheme == "http" and not self._trusted_host(host) and not self._trusted_host(origin_host):
            raise RegistryError(f"refusing plain-http redirect/realm {parts.hostname}")
        if self._trusted_host(host):
            return
        try:
            ips = await self._resolve(parts.hostname)
        except OSError as e:
            raise RegistryError(f"cannot resolve {parts.hostname}: {e}") from e
        if not ips or any(_blocked_ip(ip) for ip in ips):
            raise RegistryError(f"refusing {parts.hostname}: resolves to a private/loopback/link-local address")

    def _realm_allowed(self, registry: str, realm: str) -> bool:
        host = (urlsplit(realm).hostname or "").lower()
        if not host:
            return False
        reg_host = self.rewrite.get(registry, registry)
        api = api_host(reg_host).split(":", 1)[0].lower()
        if host in (api, reg_host.split(":", 1)[0].lower()) or host in self.realm_hosts:
            return True
        parent = _parent_domain(api)
        return bool(parent and (host == parent or host.endswith("." + parent)))

    async def _send(self, method: str, url: str, headers: dict[str, str], cap: int, *, registry: str,
                    params: dict[str, str] | None = None, auth: httpx.Auth | None = None,
                    truncate: bool = False) -> tuple[httpx.Response, bytes]:
        """One request with manual, checked redirects and a streamed, capped body.
        `truncate`: return the first `cap` bytes instead of failing past the cap."""
        client = self._ensure()
        origin = urlsplit(url).netloc.lower()
        for _hop in range(MAX_REDIRECTS + 1):
            req = client.build_request(method, url, headers=headers, params=params)
            resp = await client.send(req, stream=True, auth=auth)
            try:
                if resp.is_redirect and resp.headers.get("location"):
                    nxt = urljoin(str(resp.url), resp.headers["location"])
                    await self._check_target(nxt, origin)
                    if urlsplit(nxt).netloc.lower() != urlsplit(url).netloc.lower():
                        headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
                        auth = None
                    url, params = nxt, None
                    if method == "HEAD" or resp.status_code in (307, 308):
                        pass
                    else:
                        method = "GET"
                    continue
                limit = cap if 200 <= resp.status_code < 300 else min(cap, MAX_ERROR_BODY_BYTES)
                body = await _read_capped(resp, limit, truncate or not (200 <= resp.status_code < 300))
                return resp, body
            finally:
                await resp.aclose()
        raise RegistryError(f"{registry}: too many redirects")

    async def _token(self, registry: str, challenge: str, scope: str) -> str | None:
        scheme, params = parse_challenge(challenge)
        creds = self.auths.get(registry)
        if scheme == "basic":
            return None
        realm = params.get("realm")
        if not realm:
            return None
        if not self._realm_allowed(registry, realm):
            raise RegistryError(f"{registry}: token realm host {urlsplit(realm).hostname!r} is not the registry "
                                "host or an allowed realm (PROVENANCE_REGISTRY_AUTH_REALMS)")
        await self._check_target(realm, self.rewrite.get(registry, registry))
        query = {k: v for k, v in (("service", params.get("service")), ("scope", scope)) if v}
        auth = httpx.BasicAuth(*creds) if creds else None
        try:
            resp, body = await self._send("GET", realm, {}, MAX_TOKEN_BYTES, registry=registry, params=query,
                                          auth=auth)
        except BodyTooLarge as e:
            raise RegistryError(f"token endpoint {realm}: response too large") from e
        if resp.status_code != 200:
            raise RegistryError(f"token endpoint {realm} returned {resp.status_code}")
        try:
            data = json.loads(body)
        except ValueError as e:
            raise RegistryError(f"token endpoint {realm}: invalid JSON") from e
        if not isinstance(data, dict):
            return None
        tok = data.get("token") or data.get("access_token")
        return tok if isinstance(tok, str) else None

    async def _request(self, method: str, registry: str, repository: str, path: str,
                       headers: dict[str, str] | None = None, url: str | None = None,
                       cap: int = MAX_MANIFEST_BYTES, truncate: bool = False) -> tuple[httpx.Response, bytes]:
        self._ensure()
        assert self._sem is not None
        scope = f"repository:{repository}:pull"
        key = (registry, scope)
        full = url or f"{self._base(registry)}/v2/{repository}/{path}"
        hdrs = dict(headers or {})
        async with self._sem:
            if not self._trusted_host(self.rewrite.get(registry, registry)):
                await self._check_link_local(full)
            for _attempt in range(2):
                req_headers = dict(hdrs)
                tok = self._tokens.get(key)
                if tok:
                    req_headers["Authorization"] = f"Bearer {tok}"
                try:
                    resp, body = await asyncio.wait_for(
                        self._send(method, full, req_headers, cap, registry=registry, truncate=truncate),
                        self.timeout * 4)
                except BodyTooLarge as e:
                    raise RegistryError(f"{registry}/{repository}: response larger than {cap} bytes") from e
                except (TimeoutError, asyncio.TimeoutError) as e:
                    raise RegistryError(f"{registry}: request timed out") from e
                except httpx.HTTPError as e:
                    raise RegistryError(f"{registry}: {type(e).__name__}: {e}") from e
                if resp.status_code != 401:
                    return resp, body
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
                    return resp, body
                self._tokens[key] = tok
            return resp, body

    async def _check_link_local(self, url: str) -> None:
        """Registries named by pod specs may be in-cluster (private) but never link-local /
        loopback (cloud metadata, node-local services)."""
        host = urlsplit(url).hostname or ""
        try:
            ips = await self._resolve(host)
        except OSError:
            return  # the request itself will fail
        for ip in ips:
            a = ipaddress.ip_address(ip.split("%", 1)[0])
            if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
                a = a.ipv4_mapped
            if a.is_link_local or a.is_loopback or a.is_unspecified or a.is_multicast:
                raise RegistryError(f"refusing registry {host}: link-local/loopback address")

    async def get_manifest(self, registry: str, repository: str, reference: str) -> Manifest | None:
        resp, raw = await self._request("GET", registry, repository, f"manifests/{reference}", {"Accept": ACCEPT},
                                        cap=MAX_MANIFEST_BYTES)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise RegistryError(f"GET manifest {_fmt(registry, repository, reference)} -> {_status(resp)}")
        try:
            body = json.loads(raw)
        except ValueError as e:
            raise RegistryError(f"invalid manifest JSON for {registry}/{repository}:{reference}") from e
        digest = resp.headers.get("docker-content-digest") or "sha256:" + hashlib.sha256(raw).hexdigest()
        mt = (resp.headers.get("content-type") or "").split(";")[0].strip() or body.get("mediaType") or ""
        return Manifest(mt, digest, body if isinstance(body, dict) else {})

    async def manifest_exists(self, registry: str, repository: str, reference: str) -> bool:
        resp, _ = await self._request("HEAD", registry, repository, f"manifests/{reference}", {"Accept": ACCEPT})
        if resp.status_code == 200:
            return True
        if resp.status_code in (404, 400):  # some registries answer 400 MANIFEST_INVALID / NAME_UNKNOWN
            return False
        raise RegistryError(f"HEAD manifest {_fmt(registry, repository, reference)} -> {_status(resp)}")

    async def get_blob(self, registry: str, repository: str, digest: str, max_bytes: int = 2 * 1024 * 1024) -> bytes | None:
        cap = max(0, min(max_bytes, MAX_ATTESTATION_BYTES))
        resp, body = await self._request("GET", registry, repository, f"blobs/{digest}", cap=cap, truncate=True)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise RegistryError(f"GET blob {registry}/{repository}@{digest} -> {resp.status_code}")
        return body

    async def list_tags(self, registry: str, repository: str) -> list[str]:
        tags: list[str] = []
        budget = MAX_TAG_LIST_BYTES
        base = self._base(registry)
        url: str | None = f"{base}/v2/{repository}/tags/list?n=1000"
        for _ in range(MAX_TAG_PAGES):
            if url is None:
                break
            if budget <= 0:
                raise RegistryError(f"list tags {registry}/{repository}: tag list larger than {MAX_TAG_LIST_BYTES} bytes")
            resp, body = await self._request("GET", registry, repository, "", url=url, cap=budget)
            budget -= len(body)
            if resp.status_code == 404:
                return tags
            if resp.status_code != 200:
                raise RegistryError(f"list tags {registry}/{repository} -> {_status(resp)}")
            try:
                data = json.loads(body) or {}
            except ValueError as e:
                raise RegistryError(f"list tags {registry}/{repository}: invalid JSON") from e
            tags.extend(str(t) for t in (data.get("tags") or []) if isinstance(data, dict))
            nxt = _next_link(resp.headers.get("link"))
            if not nxt:
                url = None
            else:
                url = urljoin(base + "/", nxt)
                if urlsplit(url).netloc != urlsplit(base).netloc:
                    raise RegistryError(f"list tags {registry}/{repository}: next page on another host")
        return tags

    async def referrers(self, registry: str, repository: str, digest: str) -> list[dict[str, Any]] | None:
        """OCI 1.1 referrers API. None when the registry does not support it."""
        resp, body = await self._request("GET", registry, repository, f"referrers/{digest}",
                                         {"Accept": MT_OCI_INDEX}, cap=MAX_MANIFEST_BYTES)
        if resp.status_code != 200:
            return None
        ct = (resp.headers.get("content-type") or "").split(";")[0].strip()
        if ct and ct != MT_OCI_INDEX and "json" not in ct:
            return None
        try:
            return list((json.loads(body) or {}).get("manifests") or [])
        except (ValueError, AttributeError):
            return None


async def _read_capped(resp: httpx.Response, cap: int, truncate: bool) -> bytes:
    """Stream the (decoded) body; past `cap` either truncate or raise BodyTooLarge."""
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        buf.extend(chunk)
        if len(buf) > cap:
            if truncate:
                return bytes(buf[:cap])
            raise BodyTooLarge(cap)
    return bytes(buf)
