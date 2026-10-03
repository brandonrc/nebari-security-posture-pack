"""Keycloak realm assertions (admin REST API, read-only)."""

from __future__ import annotations

import re
from typing import Any

from ..context import EngineContext
from ..model import Result, assertion, failed, passed

C = "keycloak"
REQUIRED_EVENT_TYPES = ("LOGIN", "LOGIN_ERROR", "LOGOUT")


def _subject_allowed(name: str, allow: list[str], kinds: tuple[str, ...] = ("user", "keycloak")) -> bool:
    for a in allow:
        a = a.strip()
        if a == name:
            return True
        if ":" in a:
            kind, _, val = a.partition(":")
            if kind.lower() in kinds and val == name:
                return True
    return False


@assertion(id="kc-brute-force-protection", title="Keycloak brute-force detection locks accounts",
           controls=["AC-7"], objectives=["ac-7_obj.a", "ac-7_obj.b"], component=C, severity="high")
async def brute_force(ctx: EngineContext) -> Result:
    """Realm `bruteForceProtected` is on and `failureFactor` <= the organization-defined maximum."""
    r = await ctx.realm()
    ev = {k: r.get(k) for k in ("bruteForceProtected", "failureFactor", "permanentLockout", "waitIncrementSeconds",
                                "maxFailureWaitSeconds", "maxDeltaTimeSeconds")}
    ev["maxAllowedFailures"] = ctx.config.max_login_failures
    if not r.get("bruteForceProtected"):
        return failed("brute-force detection is disabled for the realm", **ev)
    ff = int(r.get("failureFactor") or 0)
    if ff > ctx.config.max_login_failures:
        return failed(f"lockout after {ff} failures (policy: at most {ctx.config.max_login_failures})", **ev)
    return passed(f"brute-force detection on; lockout after {ff} consecutive failures", **ev)


def parse_password_policy(policy: str | None) -> dict[str, str]:
    """`length(12) and digits(1) and notUsername(undefined)` -> {length: '12', digits: '1', notUsername: ...}."""
    out: dict[str, str] = {}
    for part in re.split(r"\s+and\s+", policy or ""):
        m = re.match(r"^\s*([A-Za-z]+)(?:\(([^)]*)\))?\s*$", part)
        if m:
            out[m.group(1)] = m.group(2) or ""
    return out


@assertion(id="kc-password-policy", title="Keycloak password policy enforces length and complexity",
           controls=["IA-5(1)"], objectives=["ia-5.1_obj.h"], component=C, severity="high")
async def password_policy(ctx: EngineContext) -> Result:
    """Realm `passwordPolicy` sets `length` >= the minimum and at least one complexity rule."""
    r = await ctx.realm()
    raw = r.get("passwordPolicy") or ""
    pol = parse_password_policy(raw)
    ev: dict[str, Any] = {"passwordPolicy": raw or None, "minLengthRequired": ctx.config.min_password_length}
    if not pol:
        return failed("no password policy is configured for the realm", **ev)
    try:
        length = int(pol.get("length") or 0)
    except ValueError:
        length = 0
    complexity = [k for k in ("digits", "upperCase", "lowerCase", "specialChars", "notUsername", "passwordHistory",
                              "passwordBlacklist") if k in pol]
    ev.update(length=length, complexityRules=complexity)
    problems = []
    if length < ctx.config.min_password_length:
        problems.append(f"minimum length {length or 'unset'} < {ctx.config.min_password_length}")
    if not complexity:
        problems.append("no complexity/history rule")
    if problems:
        return failed("password policy too weak: " + "; ".join(problems), **ev)
    return passed(f"password policy: length >= {length}, rules {', '.join(complexity)}", **ev)


@assertion(id="kc-admin-mfa", title="Administrators must use multi-factor authentication",
           controls=["IA-2(1)"], objectives=["ia-2.1_obj"], component=C, severity="critical")
async def admin_mfa(ctx: EngineContext) -> Result:
    """Every member of the admin group has an OTP or WebAuthn credential (or the realm's browser
    flow requires OTP for everyone)."""
    group_name = ctx.config.keycloak_admin_group
    groups = await ctx.kc_get("/groups", {"search": group_name, "briefRepresentation": "true"})
    group = next((g for g in groups or [] if g.get("name") == group_name), None)
    if group is None:
        return Result("not-applicable", f"no group {group_name!r} in the realm", {"group": group_name})
    members = await ctx.kc_get(f"/groups/{group['id']}/members", {"max": 1000, "briefRepresentation": "true"})
    without: list[str] = []
    with_mfa: list[str] = []
    for u in members or []:
        if not u.get("enabled", True):
            continue
        creds = await ctx.kc_get(f"/users/{u['id']}/credentials")
        types = {c.get("type") for c in creds or []}
        if types & {"otp", "webauthn", "webauthn-passwordless"}:
            with_mfa.append(u.get("username"))
        else:
            without.append(u.get("username"))
    ev = {"group": group_name, "members": len(with_mfa) + len(without), "withMfa": sorted(with_mfa),
          "withoutMfa": sorted(without)}
    if not with_mfa and not without:
        return Result("not-applicable", f"group {group_name!r} has no enabled members", ev)
    if without:
        return failed(f"{len(without)} of {len(with_mfa) + len(without)} admin(s) have no second factor: "
                      + ", ".join(sorted(without)[:10]), **ev)
    return passed(f"all {len(with_mfa)} admin(s) have an OTP/WebAuthn credential", **ev)


@assertion(id="kc-session-timeouts", title="SSO session idle and maximum lifetimes within policy",
           controls=["AC-12", "SC-10"],
           objectives=["ac-12_obj", "sc-10_obj"], component=C, severity="medium")
async def session_timeouts(ctx: EngineContext) -> Result:
    """`ssoSessionIdleTimeout` and `ssoSessionMaxLifespan` are set and <= the policy values."""
    r = await ctx.realm()
    idle, life = int(r.get("ssoSessionIdleTimeout") or 0), int(r.get("ssoSessionMaxLifespan") or 0)
    ev = {"ssoSessionIdleTimeout": idle, "ssoSessionMaxLifespan": life,
          "maxIdleSeconds": ctx.config.max_session_idle_seconds,
          "maxLifespanSeconds": ctx.config.max_session_lifespan_seconds,
          "clientSessionIdleTimeout": r.get("clientSessionIdleTimeout")}
    problems = []
    if not idle or idle > ctx.config.max_session_idle_seconds:
        problems.append(f"idle timeout {idle}s > {ctx.config.max_session_idle_seconds}s")
    if not life or life > ctx.config.max_session_lifespan_seconds:
        problems.append(f"max lifespan {life}s > {ctx.config.max_session_lifespan_seconds}s")
    if problems:
        return failed("; ".join(problems), **ev)
    return passed(f"idle {idle}s, max lifespan {life}s", **ev)


@assertion(id="kc-remember-me-disabled", title="'Remember me' is disabled", controls=["AC-12"], objectives=["ac-12_obj"], component=C,
           severity="low")
async def remember_me(ctx: EngineContext) -> Result:
    """Realm `rememberMe` is false (it would keep sessions alive across browser restarts)."""
    r = await ctx.realm()
    if r.get("rememberMe"):
        return failed("'remember me' is enabled on the login page", rememberMe=True)
    return passed("'remember me' is disabled", rememberMe=False)


@assertion(id="kc-self-registration-disabled", title="User self-registration is disabled", controls=["AC-2"], objectives=["ac-2_obj.e", "ac-2_obj.f-1"],
           component=C, severity="high")
async def registration(ctx: EngineContext) -> Result:
    """Realm `registrationAllowed` is false: accounts exist only when an administrator creates them."""
    r = await ctx.realm()
    if r.get("registrationAllowed"):
        return failed("anyone can self-register an account", registrationAllowed=True)
    return passed("self-registration is disabled", registrationAllowed=False)


@assertion(id="kc-login-events", title="Login events are recorded with retention", controls=["AU-12", "AU-11"],
           objectives=["au-12_obj.a", "au-11_obj"],
           component=C, severity="medium")
async def login_events(ctx: EngineContext) -> Result:
    """Events config: `eventsEnabled` with an expiration (stored-event retention), and the stored
    event types include successful and failed logins and logouts (`enabledEventTypes` empty = all)."""
    cfg = await ctx.kc_get("/events/config")
    ev = {k: cfg.get(k) for k in ("eventsEnabled", "eventsExpiration", "eventsListeners")}
    types = list(cfg.get("enabledEventTypes") or [])
    ev["enabledEventTypes"] = types or "all"
    ev["requiredEventTypes"] = list(REQUIRED_EVENT_TYPES)
    if not cfg.get("eventsEnabled"):
        return failed("login events are not stored (eventsEnabled=false)", **ev)
    missing = [t for t in REQUIRED_EVENT_TYPES if types and t not in types]
    if missing:
        return failed("stored event types omit " + ", ".join(missing), **ev)
    if not cfg.get("eventsExpiration"):
        return failed("login events are stored without a retention period (eventsExpiration unset)", **ev)
    return passed(f"login/logout events ({'all types' if not types else ', '.join(REQUIRED_EVENT_TYPES)}) stored "
                  f"for {int(cfg['eventsExpiration']) // 86400} day(s)", **ev)


@assertion(id="kc-admin-events", title="Admin events are recorded with details", controls=["AU-2", "AU-3", "AU-12"], objectives=["au-2_obj.c-2", "au-3_obj", "au-12_obj.c"],
           component=C, severity="medium")
async def admin_events(ctx: EngineContext) -> Result:
    """Events config: `adminEventsEnabled` and `adminEventsDetailsEnabled`."""
    cfg = await ctx.kc_get("/events/config")
    ev = {k: cfg.get(k) for k in ("adminEventsEnabled", "adminEventsDetailsEnabled")}
    if not cfg.get("adminEventsEnabled"):
        return failed("admin events are not recorded", **ev)
    if not cfg.get("adminEventsDetailsEnabled"):
        return failed("admin events are recorded without representation details", **ev)
    return passed("admin events recorded with details", **ev)


@assertion(id="kc-admin-role-allowlist", title="Realm admin role limited to approved accounts",
           controls=["AC-6(5)"], objectives=["ac-6.5_obj"], component=C, severity="high")
async def admin_role(ctx: EngineContext) -> Result:
    """Users holding the realm `admin` role (directly or through a group) are all in
    `controlsEngine.adminSubjects`."""
    role = ctx.config.keycloak_admin_role
    roles = await ctx.kc_get("/roles")
    if not any(r.get("name") == role for r in roles or []):
        return Result("not-applicable", f"realm has no {role!r} role", {"role": role})
    users = {u["username"] for u in await ctx.kc_get(f"/roles/{role}/users", {"max": 1000}) or []}
    via_groups: dict[str, list[str]] = {}
    for g in await ctx.kc_get(f"/roles/{role}/groups", {"max": 1000}) or []:
        for u in await ctx.kc_get(f"/groups/{g['id']}/members", {"max": 1000, "briefRepresentation": "true"}) or []:
            via_groups.setdefault(u["username"], []).append(g.get("name"))
    holders = sorted(users | set(via_groups))
    extra = [u for u in holders if not _subject_allowed(u, ctx.config.admin_subjects)]
    ev = {"role": role, "holders": holders, "viaGroups": via_groups, "allowlist": ctx.config.admin_subjects,
          "notAllowlisted": extra}
    if extra:
        return failed(f"{len(extra)} account(s) hold the {role!r} role without approval: " + ", ".join(extra[:10]),
                      **ev)
    return passed(f"{len(holders)} account(s) hold the {role!r} role, all approved", **ev)


@assertion(id="kc-ssl-required", title="Keycloak requires TLS for external requests", controls=["SC-8"], objectives=["sc-8_obj"],
           component=C, severity="high")
async def ssl_required(ctx: EngineContext) -> Result:
    """Realm `sslRequired` is `external` or `all` (not `none`)."""
    r = await ctx.realm()
    val = (r.get("sslRequired") or "").lower()
    if val in ("external", "all"):
        return passed(f"sslRequired={val}", sslRequired=val)
    return failed(f"sslRequired={val or 'unset'}: Keycloak accepts logins over plain HTTP", sslRequired=val or None)
