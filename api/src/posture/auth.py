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


class JWKSCache:
    """Caches the JWKS for `ttl` seconds; refetches (rate-limited) on unknown `kid`."""

    def __init__(self, url: str, ttl: float = 600, http: httpx.AsyncClient | None = None):
        self.url = url
        self.ttl = ttl
        self._http = http
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def _fetch(self) -> None:
        client = self._http or httpx.AsyncClient(timeout=10)
        try:
            r = await client.get(self.url)
            r.raise_for_status()
            data = r.json()
        finally:
            if self._http is None:
                await client.aclose()
        keys: dict[str, Any] = {}
        for jwk in data.get("keys") or []:
            if jwk.get("use") not in (None, "sig"):
                continue
            try:
                keys[jwk.get("kid") or ""] = jwt.PyJWK(jwk)
            except jwt.PyJWKError:
                continue
        self._keys = keys
        self._fetched_at = time.monotonic()
        log.info("jwks.refreshed", keys=len(keys))

    async def get_key(self, kid: str | None) -> Any:
        now = time.monotonic()
        async with self._lock:
            if not self._keys or now - self._fetched_at > self.ttl:
                await self._fetch()
            elif (kid or "") not in self._keys and now - self._fetched_at > REFETCH_MIN_INTERVAL:
                await self._fetch()
        key = self._keys.get(kid or "")
        if key is None and not kid and len(self._keys) == 1:
            key = next(iter(self._keys.values()))
        if key is None:
            raise AuthError("unknown signing key")
        return key


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
        self.jwks = jwks or JWKSCache(settings.oidc_jwks_url, settings.jwks_cache_seconds)
        if not settings.auth_disabled and not settings.oidc_issuers:
            log.warning("auth.no_issuers_configured", detail="OIDC_ISSUERS empty: issuer not restricted")

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
        except httpx.HTTPError as e:
            log.error("jwks.fetch_failed", error=str(e))
            raise AuthError("unable to fetch signing keys") from e
        options = {"require": ["exp", "iss"], "verify_aud": bool(self.settings.oidc_audience)}
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self.settings.oidc_audience or None,
                options=options,
                leeway=30,
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthError("token expired") from e
        except jwt.PyJWTError as e:
            raise AuthError("invalid token") from e
        issuers = [i.rstrip("/") for i in self.settings.oidc_issuers]
        if issuers and str(claims.get("iss", "")).rstrip("/") not in issuers:
            raise AuthError("untrusted issuer")
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
        if settings.auth_disabled:
            log.warning("auth.disabled", detail="AUTH_MODE=disabled: every request is treated as admin (dev only)")
        _authenticator = Authenticator(settings)
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
