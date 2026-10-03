"""Keycloak realm assertions (admin REST API, read-only)."""

from __future__ import annotations

import re
from typing import Any

from ..context import EngineContext
from ..model import Result, assertion, failed, passed, unknown

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
    """Realm `bruteForceProtected` is on and every AC-7 ODP holds: `failureFactor` <= the maximum
    consecutive failures; failures are counted over at least the window (`maxDeltaTimeSeconds` >=
    `lockoutWindowSeconds`, the "15 minutes"); the lockout lasts at least `minLockoutSeconds`
    (`waitIncrementSeconds` and `maxFailureWaitSeconds`) or is permanent until an administrator
    releases it (`permanentLockout`, required when `requireAdminRelease`, e.g. DoD)."""
    r = await ctx.realm()
    cfg = ctx.config
    ev = {k: r.get(k) for k in ("bruteForceProtected", "failureFactor", "permanentLockout", "waitIncrementSeconds",
                                "maxFailureWaitSeconds", "maxDeltaTimeSeconds")}
    ev.update(maxAllowedFailures=cfg.max_login_failures, lockoutWindowSeconds=cfg.lockout_window_seconds,
              minLockoutSeconds=cfg.min_lockout_seconds, requireAdminRelease=cfg.require_admin_release)
    if not r.get("bruteForceProtected"):
        return failed("brute-force detection is disabled for the realm", **ev)
    problems = []
    ff = int(r.get("failureFactor") or 0)
    if not ff or ff > cfg.max_login_failures:
        problems.append(f"lockout after {ff or 'unset'} failures (policy: at most {cfg.max_login_failures})")
    window = int(r.get("maxDeltaTimeSeconds") or 0)
    if window < cfg.lockout_window_seconds:
        problems.append(f"failures counted over {window}s (policy: at least {cfg.lockout_window_seconds}s)")
    permanent = bool(r.get("permanentLockout"))
    wait = min(int(r.get("waitIncrementSeconds") or 0), int(r.get("maxFailureWaitSeconds") or 0) or 10**9)
    if cfg.require_admin_release and not permanent:
        problems.append("temporary lockout; policy requires release by an administrator (permanentLockout)")
    elif not permanent and wait < cfg.min_lockout_seconds:
        problems.append(f"lockout lasts {wait}s (policy: at least {cfg.min_lockout_seconds}s)")
    if problems:
        return failed("brute-force settings below policy: " + "; ".join(problems), **ev)
    return passed(f"brute-force detection on: lockout after {ff} failures within {window}s, "
                  + ("until an administrator releases the account" if permanent else f"for {wait}s"), **ev)


def parse_password_policy(policy: str | None) -> dict[str, str]:
    """`length(12) and digits(1) and notUsername(undefined)` -> {length: '12', digits: '1', notUsername: ...}."""
    out: dict[str, str] = {}
    for part in re.split(r"\s+and\s+", policy or ""):
        m = re.match(r"^\s*([A-Za-z]+)(?:\(([^)]*)\))?\s*$", part)
        if m:
            out[m.group(1)] = m.group(2) or ""
    return out


@assertion(id="kc-password-policy", title="Keycloak password policy enforces length and a blocklist",
           controls=["IA-5(1)"], objectives=["ia-5.1_obj.a", "ia-5.1_obj.b", "ia-5.1_obj.h"], component=C,
           severity="high")
async def password_policy(ctx: EngineContext) -> Result:
    """Realm `passwordPolicy` sets `length` >= the organization-defined minimum (15 for the DoD
    profile) and a compromised / common password blocklist (`passwordBlacklist`). SP 800-53 rev5
    IA-5(1) replaced composition rules with a blocklist and long passphrases, so complexity rules
    alone never pass (compliance review M4/M5)."""
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
    rules = [k for k in ("digits", "upperCase", "lowerCase", "specialChars", "notUsername", "passwordHistory",
                         "maxLength") if k in pol]
    key = next((k for k in ("passwordBlacklist", "passwordBlocklist") if k in pol), None)
    blocklist = pol.get(key) if key else None
    ev.update(length=length, otherRules=rules, blocklist=blocklist if key else None)
    problems = []
    if length < ctx.config.min_password_length:
        problems.append(f"minimum length {length or 'unset'} < {ctx.config.min_password_length}")
    if key is None:
        problems.append("no compromised-password blocklist (passwordBlacklist)")
    if problems:
        return failed("password policy too weak: " + "; ".join(problems), **ev)
    return passed(f"password policy: length >= {length}, blocklist {blocklist or '(default)'}"
                  + (f", rules {', '.join(rules)}" if rules else ""), **ev)


MFA_PROVIDERS = {"auth-otp-form", "webauthn-authenticator", "webauthn-authenticator-passwordless",
                 "auth-x509-client-username-form", "auth-recovery-authn-code-form"}
X509_PROVIDERS = {"auth-x509-client-username-form"}


async def browser_flow(ctx: EngineContext) -> tuple[str, list[dict[str, Any]]]:
    r = await ctx.realm()
    alias = r.get("browserFlow") or "browser"
    from urllib.parse import quote

    return alias, list(await ctx.kc_get(f"/authentication/flows/{quote(alias, safe='')}/executions") or [])


def flow_steps(executions: list[dict[str, Any]], providers: set[str]) -> list[dict[str, Any]]:
    """Executions of `providers` in a flow with how they are enforced: `all` (REQUIRED with every
    parent sub-flow REQUIRED, top-level ALTERNATIVE paths allowed), `role` (inside a CONDITIONAL
    sub-flow with a user-role condition), `optional` (CONDITIONAL on "user configured", ALTERNATIVE
    or DISABLED)."""
    out = []
    stack: list[dict[str, Any]] = []  # ancestors by level
    for i, ex in enumerate(executions):
        level = int(ex.get("level") or 0)
        stack = stack[:level]
        if ex.get("authenticationFlow"):
            # conditions are the executions of the sub-flow (next entries at level + 1)
            kids = []
            for nxt in executions[i + 1:]:
                if int(nxt.get("level") or 0) <= level:
                    break
                if int(nxt.get("level") or 0) == level + 1:
                    kids.append(nxt.get("providerId") or "")
            stack.append({"requirement": ex.get("requirement"), "conditions": kids,
                          "name": ex.get("displayName") or ex.get("alias")})
            continue
        if (ex.get("providerId") or "") not in providers:
            continue
        req = ex.get("requirement")
        enforcement = "all" if req == "REQUIRED" else "optional"
        for depth, anc in enumerate(stack):
            areq = anc["requirement"]
            if areq == "REQUIRED" or (areq == "ALTERNATIVE" and depth == 0):
                continue
            if areq == "CONDITIONAL" and "conditional-user-role" in anc["conditions"] and \
                    "conditional-user-configured" not in anc["conditions"]:
                enforcement = "role" if enforcement != "optional" else "optional"
                continue
            enforcement = "optional"
        out.append({"provider": ex.get("providerId"), "displayName": ex.get("displayName"), "requirement": req,
                    "enforcement": enforcement, "path": [a["name"] for a in stack]})
    return out


@assertion(id="kc-admin-mfa", title="Administrators must use multi-factor authentication",
           controls=["IA-2(1)"], objectives=["ia-2.1_obj"], component=C, severity="critical")
async def admin_mfa(ctx: EngineContext) -> Result:
    """The realm's browser flow *requires* a second factor (OTP, WebAuthn or X.509) for every user or,
    through a role condition, for administrators; a flow that only asks users who configured OTP is
    optional MFA and fails. Admin-group members without an enrolled second factor are listed
    (Keycloak forces enrolment on their next login when the step is required)."""
    group_name = ctx.config.keycloak_admin_group
    alias, executions = await browser_flow(ctx)
    steps = flow_steps(executions, MFA_PROVIDERS)
    enforced = [s for s in steps if s["enforcement"] in ("all", "role")]
    groups = await ctx.kc_get("/groups", {"search": group_name, "briefRepresentation": "true"})
    group = next((g for g in groups or [] if g.get("name") == group_name), None)
    ev: dict[str, Any] = {"browserFlow": alias, "mfaSteps": steps, "group": group_name}
    if group is None:  # M5: a wrong group name is a configuration gap, never "not applicable"
        return unknown(f"admin group {group_name!r} not found in the realm (controlsEngine.keycloak.adminGroup)", **ev)
    members = await ctx.kc_get(f"/groups/{group['id']}/members", {"max": 1000, "briefRepresentation": "true"})
    without: list[str] = []
    with_mfa: list[str] = []
    for u in members or []:
        if not u.get("enabled", True):
            continue
        creds = await ctx.kc_get(f"/users/{u['id']}/credentials")
        types = {c.get("type") for c in creds or []}
        (with_mfa if types & {"otp", "webauthn", "webauthn-passwordless"} else without).append(u.get("username"))
    ev.update(members=len(with_mfa) + len(without), withMfa=sorted(with_mfa), withoutMfa=sorted(without))
    if not enforced:
        return failed(f"browser flow {alias!r} does not require a second factor"
                      + (" (MFA steps are optional: " + ", ".join(f"{s['displayName']} {s['requirement']}"
                                                                   for s in steps) + ")" if steps else ""), **ev)
    how = "every user" if any(s["enforcement"] == "all" for s in enforced) else "role-conditional"
    return passed(f"browser flow {alias!r} requires a second factor ({how}: "
                  + ", ".join(s["displayName"] or s["provider"] for s in enforced) + ")"
                  + (f"; {len(without)} admin(s) will be forced to enrol" if without else ""), **ev)


@assertion(id="kc-mfa-all-users", title="Every user must use multi-factor authentication",
           controls=["IA-2(2)"], objectives=["ia-2.2_obj"], component=C, severity="high")
async def mfa_all_users(ctx: EngineContext) -> Result:
    """The realm's browser flow requires a second factor for every user (IA-2(2), non-privileged
    accounts): a REQUIRED OTP / WebAuthn / X.509 step not limited by a role or "user configured"
    condition."""
    alias, executions = await browser_flow(ctx)
    steps = flow_steps(executions, MFA_PROVIDERS)
    ev = {"browserFlow": alias, "mfaSteps": steps}
    if any(s["enforcement"] == "all" for s in steps):
        return passed(f"browser flow {alias!r} requires a second factor for every user", **ev)
    return failed(f"browser flow {alias!r} does not require a second factor for every user", **ev)


@assertion(id="kc-x509-authenticator", title="X.509 (PIV/CAC) client certificates are accepted",
           controls=["IA-2(12)"], objectives=["ia-2.12_obj"], component=C, severity="medium")
async def x509_authenticator(ctx: EngineContext) -> Result:
    """The realm's browser flow contains an enabled X.509 client-certificate authenticator
    (`auth-x509-client-username-form`), so PIV/CAC credentials are accepted and verified (IA-2(12),
    the DoD requirement for privileged MFA per DoDI 8520.03)."""
    alias, executions = await browser_flow(ctx)
    steps = [s for s in flow_steps(executions, X509_PROVIDERS) if s["requirement"] != "DISABLED"]
    ev = {"browserFlow": alias, "x509Steps": steps}
    if steps:
        return passed(f"browser flow {alias!r} has an X.509 authenticator ({steps[0]['requirement']})", **ev)
    return failed(f"browser flow {alias!r} has no enabled X.509 client-certificate authenticator", **ev)


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
    if "rememberMe" not in r:
        return unknown("realm representation has no rememberMe field (insufficient admin view?)")
    if r.get("rememberMe"):
        return failed("'remember me' is enabled on the login page", rememberMe=True)
    return passed("'remember me' is disabled", rememberMe=False)


@assertion(id="kc-self-registration-disabled", title="User self-registration is disabled", controls=["AC-2"], objectives=["ac-2_obj.e", "ac-2_obj.f-1"],
           component=C, severity="high")
async def registration(ctx: EngineContext) -> Result:
    """Realm `registrationAllowed` is false: accounts exist only when an administrator creates them."""
    r = await ctx.realm()
    if "registrationAllowed" not in r:
        return unknown("realm representation has no registrationAllowed field (insufficient admin view?)")
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
