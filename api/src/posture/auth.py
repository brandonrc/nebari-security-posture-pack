"""JWT authentication (JWKS-verified) + admin-group authorization (DESIGN §5).

Token sources: `Authorization: Bearer <jwt>`, cookie `NebariIdToken`, or the first
cookie (sorted by name) starting with `IdToken`. Tokens are never logged.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status

from .config import Settings, get_settings
from .logs import get_logger

log = get_logger(__name__)

PINNED_COOKIE = "NebariIdToken"
COOKIE_PREFIX = "IdToken"
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
REFETCH_MIN_INTERVAL = 30.0


@dataclass
class User:
    username: str
    email: str | None = None
    groups: list[str] = field(default_factory=list)
    is_admin: bool = False
    claims: dict[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {"username": self.username, "email": self.email, "groups": self.groups, "isAdmin": self.is_admin}


class AuthError(Exception):
    pass


class AuthConfigError(RuntimeError):
    """Unsafe auth configuration: the API refuses to start (security review H1/L4)."""


class JWKSError(Exception):
    """The JWKS could not be fetched or parsed (network, HTTP status, non-JSON, bad shape)."""


MAX_JWKS_BYTES = 1 << 20


class JWKSCache:
    """Caches the JWKS for `ttl` seconds; refetches (rate-limited) on unknown `kid`.

    The lock only guards bookkeeping, never the network fetch: concurrent callers share one
    in-flight fetch (single flight), and once keys are cached an expired TTL is refreshed in the
    background while the cached keys keep serving, so a slow Keycloak cannot stall every request.
    """

    def __init__(self, url: str, ttl: float = 600, http: httpx.AsyncClient | None = None):
        self.url = url
        self.ttl = ttl
        self._http = http
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._attempted_at = 0.0
        self._lock = asyncio.Lock()
        self._inflight: asyncio.Task | None = None

    async def _fetch(self) -> None:
        client = self._http or httpx.AsyncClient(timeout=10)
        try:
            try:
                r = await client.get(self.url)
                r.raise_for_status()
                if len(r.content) > MAX_JWKS_BYTES:
                    raise JWKSError("JWKS response too large")
                data = r.json()
            except httpx.HTTPError as e:
                raise JWKSError(f"{type(e).__name__}: {e}") from e
            except ValueError as e:  # non-JSON body (e.g. an HTML error page)
                raise JWKSError("JWKS response is not JSON") from e
        finally:
            if self._http is None:
                await client.aclose()
        if not isinstance(data, dict) or not isinstance(data.get("keys") or [], list):
            raise JWKSError("JWKS response has no keys array")
        keys: dict[str, Any] = {}
        for jwk in data.get("keys") or []:
            if not isinstance(jwk, dict) or jwk.get("use") not in (None, "sig"):
                continue
            try:
                keys[jwk.get("kid") or ""] = jwt.PyJWK(jwk)
            except (jwt.PyJWKError, jwt.InvalidKeyError, TypeError, ValueError):
                continue
        self._keys = keys
        self._fetched_at = time.monotonic()
        log.info("jwks.refreshed", keys=len(keys))

    async def _start_fetch(self) -> asyncio.Task:
        async with self._lock:  # bookkeeping only; the fetch itself runs outside the lock
            if self._inflight is None or self._inflight.done():
                self._attempted_at = time.monotonic()
                self._inflight = asyncio.create_task(self._fetch())
                self._inflight.add_done_callback(_consume_task_exception)
            return self._inflight

    async def _refresh(self) -> None:
        await asyncio.shield(await self._start_fetch())

    async def get_key(self, kid: str | None) -> Any:
        now = time.monotonic()
        if not self._keys:
            await self._refresh()
        elif (kid or "") not in self._keys:
            if now - max(self._fetched_at, self._attempted_at) > REFETCH_MIN_INTERVAL:
                await self._refresh()
        elif now - self._fetched_at > self.ttl and now - self._attempted_at > REFETCH_MIN_INTERVAL:
            await self._start_fetch()  # stale-while-revalidate: do not wait
        key = self._keys.get(kid or "")
        if key is None and not kid and len(self._keys) == 1:
            key = next(iter(self._keys.values()))
        if key is None:
            raise AuthError("unknown signing key")
        return key


def _consume_task_exception(task: asyncio.Task) -> None:
    if not task.cancelled() and (exc := task.exception()) is not None:
        log.warning("jwks.fetch_failed", error=str(exc)[:200])


def check_auth_config(settings: Settings) -> None:
    """Fail closed at startup (security review H1, L4)."""
    if settings.auth_disabled:
        if not settings.posture_dev:
            raise AuthConfigError("AUTH_MODE=disabled is only allowed for local development with POSTURE_DEV=1")
        return
    if settings.auth_mode.lower() != "oidc":
        raise AuthConfigError(f"unknown AUTH_MODE {settings.auth_mode!r} (expected oidc or disabled)")
    if not settings.oidc_issuers:
        raise AuthConfigError("AUTH_MODE=oidc requires OIDC_ISSUERS (comma list of accepted token issuers); "
                              "refusing to start rather than accept any issuer")
    if not settings.accepted_audiences:
        log.warning("auth.no_audience_configured",
                    detail="OIDC_CLIENT_IDS/OIDC_AUDIENCES empty: aud/azp not checked; tokens minted for any "
                           "client of the realm are accepted")


def token_from_request(request: Request) -> str | None:
    authz = request.headers.get("authorization") or ""
    if authz.lower().startswith("bearer "):
        tok = authz[7:].strip()
        if tok:
            return tok
    cookies = request.cookies
    if cookies.get(PINNED_COOKIE):
        return cookies[PINNED_COOKIE]
    for name in sorted(cookies):
        if name.startswith(COOKIE_PREFIX) and cookies[name]:
            return cookies[name]
    return None


def normalize_groups(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [str(g).lstrip("/") for g in raw if str(g).strip()]


class Authenticator:
    def __init__(self, settings: Settings, jwks: JWKSCache | None = None):
        self.settings = settings
        check_auth_config(settings)
        self.jwks = jwks or JWKSCache(settings.oidc_jwks_url, settings.jwks_cache_seconds)
        self.audiences = set(settings.accepted_audiences)

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise AuthError("malformed token") from e
        alg = header.get("alg")
        if alg not in ALGORITHMS:
            raise AuthError("unsupported token algorithm")
        try:
            key = await self.jwks.get_key(header.get("kid"))
        except JWKSError as e:
            log.error("jwks.fetch_failed", error=str(e)[:200])
            raise AuthError("unable to fetch signing keys") from e
        jwk_alg = getattr(key, "_jwk_data", {}).get("alg")
        if jwk_alg and jwk_alg != alg:
            raise AuthError("token algorithm does not match the signing key")
        options = {"require": ["exp", "iss"], "verify_aud": False}  # aud/azp checked below
        try:
            claims = jwt.decode(token, key=key, algorithms=[alg], options=options, leeway=30)
        except jwt.ExpiredSignatureError as e:
            raise AuthError("token expired") from e
        except jwt.PyJWTError as e:
            raise AuthError("invalid token") from e
        issuers = [i.rstrip("/") for i in self.settings.oidc_issuers]
        if str(claims.get("iss", "")).rstrip("/") not in issuers:
            raise AuthError("untrusted issuer")
        if self.audiences:
            aud = claims.get("aud")
            auds = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()
            if not (auds & self.audiences) and claims.get("azp") not in self.audiences:
                raise AuthError("token not issued for this client (aud/azp)")
        return claims

    def user_from_claims(self, claims: dict[str, Any]) -> User:
        groups = normalize_groups(claims.get("groups"))
        username = claims.get("preferred_username") or claims.get("email") or claims.get("sub") or "unknown"
        return User(
            username=str(username),
            email=claims.get("email"),
            groups=groups,
            is_admin=bool(set(groups) & self.settings.admin_group_set),
            claims=claims,
        )

    async def authenticate(self, request: Request) -> User:
        if self.settings.auth_disabled:
            return User(username="dev", email=None, groups=sorted(self.settings.admin_group_set), is_admin=True)
        token = token_from_request(request)
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="authentication required",
                                headers={"WWW-Authenticate": "Bearer"})
        try:
            claims = await self.verify(token)
        except AuthError as e:
            log.info("auth.rejected", reason=str(e), path=request.url.path)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid token",
                                headers={"WWW-Authenticate": "Bearer"}) from e
        return self.user_from_claims(claims)


_authenticator: Authenticator | None = None


def get_authenticator() -> Authenticator:
    global _authenticator
    if _authenticator is None:
        settings = get_settings()
        _authenticator = Authenticator(settings)  # raises AuthConfigError on unsafe config
        if settings.auth_disabled:
            log.warning("auth.disabled", detail="AUTH_MODE=disabled: every request is treated as admin (dev only)")
    return _authenticator


def set_authenticator(auth: Authenticator | None) -> None:
    global _authenticator
    _authenticator = auth


async def current_user(request: Request) -> User:
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    user = await get_authenticator().authenticate(request)
    request.state.user = user
    return user


async def require_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="admin group required")
    return user
