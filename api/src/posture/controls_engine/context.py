"""Assertion context: configuration, Kubernetes API (read-only raw GETs), Keycloak admin
client, HTTP client and the latest scan snapshot. Everything an assertion touches goes through
here so tests can substitute fakes (see tests/controls_engine/fakes.py)."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from ..logs import get_logger

log = get_logger(__name__)

DEFAULT_SYSTEM_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")
IN_APP_AUTH_ANNOTATION = "posture.nebari.dev/in-app-auth"


# --------------------------------------------------------------------------- errors
class EngineError(Exception):
    """Base: an assertion that raises one of these is recorded as `unknown`."""


class K8sError(EngineError):
    def __init__(self, path: str, status: int | None, message: str = ""):
        self.path, self.status = path, status
        super().__init__(f"GET {path}: {status or ''} {message}".strip())


class K8sNotFound(K8sError):
    pass


class K8sForbidden(K8sError):
    pass


class KeycloakError(EngineError):
    pass


class NotConfigured(EngineError):
    pass


# --------------------------------------------------------------------------- config
@dataclass
class EngineConfig:
    baseline: str = "moderate"
    system_namespaces: list[str] = field(default_factory=lambda: list(DEFAULT_SYSTEM_NAMESPACES))
    admin_subjects: list[str] = field(default_factory=list)
    # Keycloak
    keycloak_url: str = "http://keycloak-keycloakx-http.keycloak.svc.cluster.local:80/auth"
    keycloak_realm: str = "nebari"
    keycloak_admin_realm: str = ""  # "" = the target realm (master only with keycloak_allow_master_fallback)
    # KEYCLOAK_ALLOW_MASTER_FALLBACK=true: with no pinned admin realm, retry the login against `master`
    # (a super-admin credential). Off by default: least privilege (security review M4).
    keycloak_allow_master_fallback: bool = field(default_factory=lambda: _env_bool("KEYCLOAK_ALLOW_MASTER_FALLBACK"))
    keycloak_client_id: str = "admin-cli"
    keycloak_admin_secret_name: str = "nebari-realm-admin-credentials"
    keycloak_admin_secret_namespace: str = "keycloak"
    keycloak_admin_group: str = "admin"
    keycloak_admin_role: str = "admin"
    keycloak_verify_tls: bool = True
    # organization-defined parameters (FedRAMP moderate values by default)
    max_login_failures: int = 3
    min_password_length: int = 12
    max_session_idle_seconds: int = 900
    max_session_lifespan_seconds: int = 43200
    min_log_retention_days: int = 90
    cert_renewal_window_days: int = 30
    # services ("" = discover)
    loki_url: str = ""
    prometheus_url: str = ""
    alertmanager_url: str = ""
    registry_url: str = ""
    log_window_minutes: int = 10
    discover_cluster_ip: bool = False  # discovered URLs use the ClusterIP instead of the DNS name
    # this pack
    scan_interval_hours: float = 6
    freshness_hours: float = 72
    # execution
    timeout_seconds: float = 30
    tls_probe: bool = True


# --------------------------------------------------------------------------- kubernetes
class KubeAPI(Protocol):
    async def get(self, path: str, query: dict[str, Any] | None = None) -> dict[str, Any]: ...


class KubeClient:
    """Read-only raw GETs through the official client (in a thread); in-cluster or kubeconfig."""

    def __init__(self, request_timeout: float = 15):
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self._api = client.ApiClient()
        self._timeout = request_timeout

    def _get_sync(self, path: str, query: dict[str, Any] | None) -> dict[str, Any]:
        from kubernetes.client.exceptions import ApiException

        try:
            resp = self._api.call_api(path, "GET", query_params=list((query or {}).items()),
                                      header_params={"Accept": "application/json"}, auth_settings=["BearerToken"],
                                      _preload_content=False, _return_http_data_only=True,
                                      _request_timeout=self._timeout)
        except ApiException as e:
            if e.status == 404:
                raise K8sNotFound(path, 404, "not found") from None
            if e.status in (401, 403):
                raise K8sForbidden(path, e.status, "forbidden (RBAC)") from None
            raise K8sError(path, e.status, str(e.reason or "")) from None
        return json.loads(resp.data)

    async def get(self, path: str, query: dict[str, Any] | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(self._get_sync, path, query)


async def list_items(api: KubeAPI, path: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cont: str | None = None
    while True:
        q: dict[str, Any] = {"limit": 500}
        if cont:
            q["continue"] = cont
        data = await api.get(path, q)
        items.extend(data.get("items") or [])
        cont = (data.get("metadata") or {}).get("continue")
        if not cont:
            return items


# --------------------------------------------------------------------------- keycloak
class KeycloakAdmin:
    """Keycloak admin REST client for one realm.

    Credentials (from the admin Secret): `username`/`password` (password grant) or
    `client-id`/`client-secret` (client-credentials grant of a service-account client holding
    realm-management roles). They may belong to the **master** realm (Keycloak super-admin,
    administers every realm) or to the **target** realm (a realm admin with realm-management
    roles). `admin_realm` pins which; empty uses the target realm, and also tries master only
    when `allow_master_fallback` (KEYCLOAK_ALLOW_MASTER_FALLBACK=true).

    Preferred setup (security review M4): a dedicated confidential client in the target realm with
    a service account holding only realm-management `view-realm`, `view-users`, `view-events`,
    given to the worker as KEYCLOAK_CLIENT_ID / KEYCLOAK_CLIENT_SECRET (client_credentials grant).
    """

    def __init__(self, http: httpx.AsyncClient, base_url: str, realm: str, credentials: dict[str, str],
                 admin_realm: str = "", client_id: str = "admin-cli", allow_master_fallback: bool = False):
        self.http = http
        self.base = base_url.rstrip("/")
        self.realm = realm
        self.creds = credentials
        self.admin_realm = (credentials.get("realm") or admin_realm or "").strip()
        self.client_id = credentials.get("client-id") or credentials.get("client_id") or client_id
        self.allow_master_fallback = allow_master_fallback
        self._token: str | None = None
        self._expires = 0.0
        self.token_realm: str | None = None
        self._lock = asyncio.Lock()
        self._error: KeycloakError | None = None  # a failed login is not retried within one engine run

    def _grant(self) -> dict[str, str]:
        secret = self.creds.get("client-secret") or self.creds.get("client_secret")
        if secret and not self.creds.get("password"):
            return {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": secret}
        if not self.creds.get("username") or not self.creds.get("password"):
            raise KeycloakError("admin credentials need username+password or client-id+client-secret")
        body = {"grant_type": "password", "client_id": self.client_id, "username": self.creds["username"],
                "password": self.creds["password"]}
        if secret:
            body["client_secret"] = secret
        return body

    async def token(self) -> str:
        async with self._lock:
            if self._token and time.monotonic() < self._expires:
                return self._token
            if self._error is not None:
                raise self._error
            try:
                return await self._login()
            except KeycloakError as e:
                self._error = e
                raise

    async def _login(self) -> str:
        if self.admin_realm:
            realms = [self.admin_realm]
        elif self.allow_master_fallback:
            realms = list(dict.fromkeys([self.realm, "master"]))
        else:
            realms = [self.realm]
        errors = []
        for r in realms:
            try:
                resp = await self.http.post(f"{self.base}/realms/{r}/protocol/openid-connect/token",
                                            data=self._grant())
            except httpx.HTTPError as e:
                raise KeycloakError(f"token request to {self.base} failed: {type(e).__name__} {e}".strip()) from None
            if resp.status_code == 200:
                body = resp.json()
                self._token = body["access_token"]
                self._expires = time.monotonic() + max(10, int(body.get("expires_in", 60)) - 15)
                self.token_realm = r
                return self._token
            errors.append(f"{r}: HTTP {resp.status_code}")
        raise KeycloakError("admin login failed (" + "; ".join(errors) + ")")

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        tok = await self.token()
        url = f"{self.base}/admin/realms/{self.realm}{path}"
        try:
            resp = await self.http.get(url, params=params, headers={"Authorization": f"Bearer {tok}"})
        except httpx.HTTPError as e:
            raise KeycloakError(f"GET {path}: {type(e).__name__}: {e}") from None
        if resp.status_code != 200:
            raise KeycloakError(f"GET {path}: HTTP {resp.status_code}")
        return resp.json()


def env_client_credentials() -> dict[str, str] | None:
    """KEYCLOAK_CLIENT_ID + KEYCLOAK_CLIENT_SECRET (or KEYCLOAK_CLIENT_SECRET_FILE): a dedicated
    view-only service-account client. Read at run time and never stored on EngineConfig, which is
    serialised into evidence."""
    cid = os.environ.get("KEYCLOAK_CLIENT_ID", "").strip()
    secret = os.environ.get("KEYCLOAK_CLIENT_SECRET", "").strip()
    path = os.environ.get("KEYCLOAK_CLIENT_SECRET_FILE", "").strip()
    if not secret and path:
        try:
            with open(path, encoding="utf-8") as f:
                secret = f.read().strip()
        except OSError as e:
            log.warning("controls.keycloak_client_secret_unreadable", path=path, error=type(e).__name__)
    if cid and secret:
        return {"client-id": cid, "client-secret": secret}
    return None


async def keycloak_credentials(api: KubeAPI, namespace: str, name: str) -> dict[str, str]:
    data = (await api.get(f"/api/v1/namespaces/{namespace}/secrets/{name}")).get("data") or {}
    return {k: base64.b64decode(v).decode("utf-8", "replace") for k, v in data.items()}


# --------------------------------------------------------------------------- context
@dataclass
class EngineContext:
    config: EngineConfig
    k8s: KubeAPI | None = None
    keycloak: KeycloakAdmin | Any | None = None
    http: httpx.AsyncClient | Any | None = None
    snapshot: dict[str, Any] | None = field(default_factory=dict)  # None = scan evidence unavailable
    keycloak_error: str | None = None  # why `keycloak` is None
    _memo: dict[str, Any] = field(default_factory=dict, repr=False)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict, repr=False)

    async def memo(self, key: str, fn: Callable[[], Awaitable[Any]]) -> Any:
        """Compute once per run (shared by every assertion); exceptions are cached too."""
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key not in self._memo:
                try:
                    self._memo[key] = ("ok", await fn())
                except Exception as e:  # noqa: BLE001
                    self._memo[key] = ("err", e)
        kind, val = self._memo[key]
        if kind == "err":
            raise val
        return val

    # ---- kubernetes helpers
    def require_k8s(self) -> KubeAPI:
        if self.k8s is None:
            raise NotConfigured("no Kubernetes API access")
        return self.k8s

    async def k8s_get(self, path: str) -> dict[str, Any]:
        api = self.require_k8s()
        return await self.memo(f"get:{path}", lambda: api.get(path))

    async def k8s_list(self, path: str) -> list[dict[str, Any]]:
        api = self.require_k8s()
        return await self.memo(f"list:{path}", lambda: list_items(api, path))

    async def k8s_list_optional(self, path: str) -> list[dict[str, Any]] | None:
        """None when the resource type is not installed (404)."""
        try:
            return await self.k8s_list(path)
        except K8sNotFound:
            return None

    def is_system_namespace(self, ns: str) -> bool:
        return ns in self.config.system_namespaces

    async def namespaces(self) -> list[dict[str, Any]]:
        return await self.k8s_list("/api/v1/namespaces")

    async def app_namespaces(self) -> list[dict[str, Any]]:
        """Non-system, active namespaces."""
        return [n for n in await self.namespaces()
                if not self.is_system_namespace(n["metadata"]["name"])
                and (n.get("status") or {}).get("phase", "Active") == "Active"]

    async def pods(self) -> list[dict[str, Any]]:
        return await self.k8s_list("/api/v1/pods")

    async def services(self) -> list[dict[str, Any]]:
        return await self.k8s_list("/api/v1/services")

    async def nebariapps(self) -> list[dict[str, Any]] | None:
        return await self.k8s_list_optional("/apis/reconcilers.nebari.dev/v1/nebariapps")

    # ---- keycloak helpers
    def require_keycloak(self) -> Any:
        if self.keycloak is None:
            raise NotConfigured(self.keycloak_error or "Keycloak admin client not configured")
        return self.keycloak

    async def kc_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        kc = self.require_keycloak()
        key = f"kc:{path}:{sorted((params or {}).items())}"
        return await self.memo(key, lambda: kc.get(path, params))

    async def realm(self) -> dict[str, Any]:
        return await self.kc_get("")

    # ---- HTTP helpers
    async def http_get(self, url: str, **kw: Any) -> httpx.Response:
        if self.http is None:
            raise NotConfigured("no HTTP client")
        return await self.http.get(url, **kw)

    async def discover_service_url(self, cache_key: str, match: Callable[[dict[str, Any], dict[str, Any]], bool],
                                   scheme: str = "http") -> list[str]:
        """URLs (`scheme://<name>.<ns>.svc.cluster.local:<port>`) of Services/ports accepted by `match(svc, port)`."""
        async def find() -> list[str]:
            out = []
            for svc in await self.services():
                spec = svc.get("spec") or {}
                if spec.get("clusterIP") in (None, "None") and spec.get("type", "ClusterIP") == "ClusterIP":
                    continue  # headless
                for port in spec.get("ports") or []:
                    if match(svc, port):
                        m = svc["metadata"]
                        host = (spec["clusterIP"] if self.config.discover_cluster_ip and spec.get("clusterIP")
                                else f"{m['name']}.{m['namespace']}.svc.cluster.local")
                        out.append(f"{scheme}://{host}:{port['port']}")
            return out

        return await self.memo(f"discover:{cache_key}", find)


async def build_context(config: EngineConfig, snapshot: dict[str, Any] | None,
                        k8s: KubeAPI | None = None, http: httpx.AsyncClient | None = None,
                        keycloak: Any | None = None) -> EngineContext:
    """Production wiring: real Kubernetes client (unless given), Keycloak admin client from the
    admin Secret. Failures are recorded, never raised: affected assertions become `unknown`."""
    if k8s is None:
        try:
            k8s = await asyncio.to_thread(KubeClient)
        except Exception as e:  # noqa: BLE001
            log.warning("controls.k8s_unavailable", error=str(e)[:300])
            k8s = None
    if http is None:
        http = httpx.AsyncClient(timeout=10, verify=config.keycloak_verify_tls, follow_redirects=False)
    ctx = EngineContext(config=config, k8s=k8s, http=http, snapshot=snapshot)
    if keycloak is not None:
        ctx.keycloak = keycloak
    elif not config.keycloak_url:
        ctx.keycloak_error = "Keycloak URL not configured (controlsEngine.keycloak.url)"
    elif (sa := env_client_credentials()) is not None:
        # dedicated client_credentials client: no admin Secret read at all
        ctx.keycloak = KeycloakAdmin(http, config.keycloak_url, config.keycloak_realm, sa,
                                     config.keycloak_admin_realm, sa["client-id"],
                                     config.keycloak_allow_master_fallback)
    elif k8s is None:
        ctx.keycloak_error = "Keycloak admin secret unreadable: no Kubernetes API access"
    else:
        try:
            creds = await keycloak_credentials(k8s, config.keycloak_admin_secret_namespace,
                                               config.keycloak_admin_secret_name)
            ctx.keycloak = KeycloakAdmin(http, config.keycloak_url, config.keycloak_realm, creds,
                                         config.keycloak_admin_realm, config.keycloak_client_id,
                                         config.keycloak_allow_master_fallback)
        except EngineError as e:
            ctx.keycloak_error = (f"Keycloak admin secret {config.keycloak_admin_secret_namespace}/"
                                  f"{config.keycloak_admin_secret_name} unreadable: {e}")
    return ctx
