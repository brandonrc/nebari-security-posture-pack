"""Envoy Gateway / Gateway API and NebariApp exposure assertions."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

from ..context import IN_APP_AUTH_ANNOTATION, EngineContext
from ..model import Result, assertion, failed, not_applicable, passed

GW = "envoy-gateway"
OP = "nebari-operator"
GATEWAYS = "/apis/gateway.networking.k8s.io/v1/gateways"
HTTPROUTES = "/apis/gateway.networking.k8s.io/v1/httproutes"
SECURITY_POLICIES = "/apis/gateway.envoyproxy.io/v1alpha1/securitypolicies"
CLIENT_TRAFFIC_POLICIES = "/apis/gateway.envoyproxy.io/v1alpha1/clienttrafficpolicies"
TLS_ORDER = {"1.0": 0, "1.1": 1, "1.2": 2, "1.3": 3, "auto": 2}


def _name(o: dict[str, Any]) -> str:
    return f"{o['metadata'].get('namespace', '')}/{o['metadata']['name']}".lstrip("/")


def _cond(obj: dict[str, Any], ctype: str) -> bool:
    return any(c.get("type") == ctype and c.get("status") == "True" for c in (obj.get("conditions") or []))


def _targets(policy: dict[str, Any]) -> list[dict[str, Any]]:
    spec = policy.get("spec") or {}
    return [*(spec.get("targetRefs") or []), *([spec["targetRef"]] if spec.get("targetRef") else [])]


def attached_routes(gw: dict[str, Any], listener: dict[str, Any], routes: list[dict[str, Any]]) -> list[dict]:
    """HTTPRoutes attached to one listener (parentRef by name/namespace, sectionName or port)."""
    gname, gns = gw["metadata"]["name"], gw["metadata"]["namespace"]
    out = []
    for r in routes:
        rns = r["metadata"]["namespace"]
        for p in (r.get("spec") or {}).get("parentRefs") or []:
            if p.get("kind", "Gateway") != "Gateway" or p.get("name") != gname or p.get("namespace", rns) != gns:
                continue
            if p.get("sectionName") and p["sectionName"] != listener.get("name"):
                continue
            if p.get("port") and p["port"] != listener.get("port"):
                continue
            out.append(r)
            break
    return out


def redirects_to_https(route: dict[str, Any]) -> bool:
    rules = (route.get("spec") or {}).get("rules") or [{}]
    for rule in rules:
        if not any(f.get("type") == "RequestRedirect" and (f.get("requestRedirect") or {}).get("scheme") == "https"
                   for f in rule.get("filters") or []):
            return False
    return True


@assertion(id="gw-https-listener", title="Gateways serve HTTPS with a certificate", controls=["SC-8", "SC-23"], objectives=["sc-8_obj", "sc-23_obj"],
           component=GW, severity="high")
async def https_listener(ctx: EngineContext) -> Result:
    """Every Gateway has a programmed HTTPS/TLS listener in Terminate mode with a certificate."""
    gws = await ctx.k8s_list_optional(GATEWAYS)
    if gws is None:
        return not_applicable("Gateway API is not installed")
    if not gws:
        return not_applicable("no Gateway resources")
    ok, bad = [], []
    for gw in gws:
        lstatus = {s.get("name"): s for s in (gw.get("status") or {}).get("listeners") or []}
        good = []
        for li in (gw.get("spec") or {}).get("listeners") or []:
            tls = li.get("tls") or {}
            if li.get("protocol") in ("HTTPS", "TLS") and tls.get("mode", "Terminate") == "Terminate" \
                    and tls.get("certificateRefs") and _cond(lstatus.get(li.get("name")) or {}, "Programmed"):
                good.append({"listener": li.get("name"), "port": li.get("port"),
                             "certificates": [c.get("name") for c in tls["certificateRefs"]]})
        (ok if good else bad).append({"gateway": _name(gw), "httpsListeners": good})
    if bad:
        return failed(f"{len(bad)} gateway(s) without a programmed HTTPS listener: "
                      + ", ".join(b["gateway"] for b in bad), gateways=ok + bad)
    return passed(f"{len(ok)} gateway(s) terminate TLS on a programmed HTTPS listener", gateways=ok)


@assertion(id="gw-http-redirect", title="Plain-HTTP listeners only redirect to HTTPS", controls=["SC-8", "SC-23"], objectives=["sc-8_obj", "sc-23_obj"],
           component=GW, severity="high")
async def http_redirect(ctx: EngineContext) -> Result:
    """Every HTTPRoute attached to an HTTP (port 80) listener redirects all rules to `https`."""
    gws = await ctx.k8s_list_optional(GATEWAYS)
    if gws is None:
        return not_applicable("Gateway API is not installed")
    routes = await ctx.k8s_list(HTTPROUTES)
    listeners, offenders, redirects = [], [], []
    for gw in gws:
        for li in (gw.get("spec") or {}).get("listeners") or []:
            if li.get("protocol") != "HTTP":
                continue
            att = attached_routes(gw, li, routes)
            listeners.append({"gateway": _name(gw), "listener": li.get("name"), "port": li.get("port"),
                              "attachedRoutes": len(att)})
            for r in att:
                (redirects if redirects_to_https(r) else offenders).append(
                    {"route": _name(r), "hostnames": (r.get("spec") or {}).get("hostnames") or [],
                     "listener": f"{_name(gw)}:{li.get('name')}"})
    ev = {"httpListeners": listeners, "plainHttpRoutes": offenders, "redirectRoutes": redirects}
    if not listeners:
        return passed("no plain-HTTP listeners", **ev)
    if offenders:
        return failed(f"{len(offenders)} route(s) serve content over plain HTTP: "
                      + ", ".join(o["route"] for o in offenders[:10]), **ev)
    return passed(f"{len(listeners)} HTTP listener(s); every attached route redirects to HTTPS", **ev)


async def _tls_probe(host: str, port: int, max_version: ssl.TLSVersion | None, timeout: float = 5) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if max_version is not None:
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = max_version
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError) as e:
            return {"handshake": "client-unsupported", "error": str(e)}
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout)
    except ssl.SSLError as e:
        msg = str(e)
        client_side = "no protocols available" in msg or "NO_PROTOCOLS" in msg.upper()
        return {"handshake": "client-unsupported" if client_side else "rejected", "error": msg[:200]}
    except (OSError, TimeoutError, asyncio.TimeoutError) as e:
        return {"handshake": "unreachable", "error": f"{type(e).__name__}: {e}"[:200]}
    sslobj = writer.get_extra_info("ssl_object")
    out = {"handshake": "ok", "version": sslobj.version() if sslobj else None,
           "cipher": (sslobj.cipher() or [None])[0] if sslobj else None}
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return out


@assertion(id="gw-tls-min-version", title="Gateway TLS minimum version is 1.2 or later",
           controls=["SC-8(1)", "SC-13"], objectives=["sc-8.1_obj", "sc-13_obj.b"], component=GW, severity="high")
async def tls_min_version(ctx: EngineContext) -> Result:
    """ClientTrafficPolicy `tls.minVersion` >= 1.2 for every Gateway; without a policy the Envoy
    Gateway default (1.2) applies and is confirmed by a live handshake probe (TLS 1.1 must be refused)."""
    gws = await ctx.k8s_list_optional(GATEWAYS)
    if gws is None:
        return not_applicable("Gateway API is not installed")
    if not gws:
        return not_applicable("no Gateway resources")
    ctps = await ctx.k8s_list_optional(CLIENT_TRAFFIC_POLICIES) or []
    per_gw, bad = [], []
    for gw in gws:
        gname, gns = gw["metadata"]["name"], gw["metadata"]["namespace"]
        pol = next((p for p in ctps if p["metadata"]["namespace"] == gns and any(
            t.get("kind") == "Gateway" and t.get("name") == gname for t in _targets(p))), None)
        entry: dict[str, Any] = {"gateway": _name(gw), "clientTrafficPolicy": _name(pol) if pol else None}
        min_v = (((pol or {}).get("spec") or {}).get("tls") or {}).get("minVersion")
        if min_v:
            entry["minVersion"] = min_v
            if TLS_ORDER.get(str(min_v), 0) < 2:
                bad.append(entry)
        else:
            entry["minVersion"] = "1.2 (Envoy Gateway default)"
            addr = next((a.get("value") for a in (gw.get("status") or {}).get("addresses") or []), None)
            port = next((li.get("port") for li in gw["spec"].get("listeners") or [] if li.get("protocol") == "HTTPS"),
                        None)
            if ctx.config.tls_probe and addr and port:
                legacy = await _tls_probe(addr, int(port), ssl.TLSVersion.TLSv1_1)
                modern = await _tls_probe(addr, int(port), None)
                entry["probe"] = {"target": f"{addr}:{port}", "tls1.1": legacy, "default": modern}
                if legacy.get("handshake") == "ok":
                    entry["minVersion"] = f"<= {legacy.get('version')} (accepted by live probe)"
                    bad.append(entry)
        per_gw.append(entry)
    if bad:
        return failed(f"{len(bad)} gateway(s) accept TLS below 1.2: " + ", ".join(b["gateway"] for b in bad),
                      gateways=per_gw)
    return passed("TLS >= 1.2 on every gateway (" + "; ".join(
        f"{g['gateway']}: {g['minVersion']}" for g in per_gw) + ")", gateways=per_gw)


def _app_routes(app: dict[str, Any], routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    name, ns = app["metadata"]["name"], app["metadata"]["namespace"]
    owned = [r for r in routes if r["metadata"]["namespace"] == ns and any(
        o.get("kind") == "NebariApp" and o.get("name") == name for o in r["metadata"].get("ownerReferences") or [])]
    return owned or [r for r in routes if r["metadata"]["namespace"] == ns and r["metadata"]["name"].startswith(name)]


def _protected_route_names(app: dict[str, Any], routes: list[dict[str, Any]]) -> list[str]:
    """Routes of the app that are not its explicit public route (`*-public-route`)."""
    return [r["metadata"]["name"] for r in _app_routes(app, routes) if not r["metadata"]["name"].endswith("-public-route")]


@assertion(id="app-gateway-auth", title="Authenticated NebariApps are enforced at the gateway",
           controls=["AC-3", "IA-2"], objectives=["ac-3_obj", "ia-2_obj-1"], component=OP, severity="critical")
async def app_gateway_auth(ctx: EngineContext) -> Result:
    """Each NebariApp with `auth.enabled` has a SecurityPolicy (oidc/jwt/extAuth) targeting its
    HTTPRoute, or `enforceAtGateway: false` plus annotation `posture.nebari.dev/in-app-auth`
    documenting the in-application check."""
    apps = await ctx.nebariapps()
    if apps is None:
        return not_applicable("NebariApp CRD is not installed")
    routes = await ctx.k8s_list(HTTPROUTES)
    sps = await ctx.k8s_list_optional(SECURITY_POLICIES) or []
    enforced, documented, offenders, unauthenticated = [], [], [], []
    for app in apps:
        spec = app.get("spec") or {}
        auth = spec.get("auth") or {}
        name = _name(app)
        if not auth.get("enabled"):
            unauthenticated.append(name)
            continue
        ns = app["metadata"]["namespace"]
        if auth.get("enforceAtGateway", True) is False:
            note = (app["metadata"].get("annotations") or {}).get(IN_APP_AUTH_ANNOTATION)
            (documented if note else offenders).append(
                {"app": name, "enforceAtGateway": False, "inAppAuth": note,
                 "reason": None if note else f"enforceAtGateway=false without annotation {IN_APP_AUTH_ANNOTATION}"})
            continue
        targets = _protected_route_names(app, routes)
        covering = [p for p in sps if p["metadata"]["namespace"] == ns
                    and any(t.get("kind") == "HTTPRoute" and t.get("name") in targets for t in _targets(p))
                    and any(k in (p.get("spec") or {}) for k in ("oidc", "jwt", "extAuth", "basicAuth"))]
        if targets and covering:
            enforced.append({"app": name, "routes": targets, "securityPolicies": [_name(p) for p in covering]})
        else:
            offenders.append({"app": name, "routes": targets,
                              "reason": "no HTTPRoute found" if not targets else "no SecurityPolicy targets the route"})
    ev = {"enforced": enforced, "documentedInApp": documented, "offenders": offenders,
          "authDisabled": unauthenticated}
    total = len(enforced) + len(documented) + len(offenders)
    if total == 0:
        return not_applicable("no NebariApp has auth.enabled", **ev)
    if offenders:
        return failed(f"{len(offenders)} of {total} authenticated app(s) not enforced at the gateway: "
                      + ", ".join(o["app"] for o in offenders[:10]), **ev)
    return passed(f"{total} authenticated app(s): {len(enforced)} gateway SecurityPolicy, "
                  f"{len(documented)} documented in-app", **ev)


@assertion(id="app-landing-visibility", title="Landing-page visibility matches app authorization",
           controls=["AC-3", "AC-22"], objectives=["ac-3_obj", "ac-22_obj.d-1"], component=OP, severity="medium")
async def app_landing_visibility(ctx: EngineContext) -> Result:
    """For NebariApps listed on the landing page with `auth.enabled`, the reconciled
    `status.serviceDiscovery.visibility` is not `public` and `requiredGroups` equals `auth.groups`."""
    apps = await ctx.nebariapps()
    if apps is None:
        return not_applicable("NebariApp CRD is not installed")
    consistent, offenders = [], []
    for app in apps:
        spec = app.get("spec") or {}
        auth, landing = spec.get("auth") or {}, spec.get("landingPage") or {}
        if not landing.get("enabled") or not auth.get("enabled"):
            continue
        sd = (app.get("status") or {}).get("serviceDiscovery") or {}
        vis = sd.get("visibility")
        want = sorted(g.lstrip("/") for g in auth.get("groups") or [])
        have = sorted(g.lstrip("/") for g in sd.get("requiredGroups") or [])
        entry = {"app": _name(app), "visibility": vis, "authGroups": want, "requiredGroups": have}
        if vis is None:
            entry["reason"] = "operator has not reported serviceDiscovery status"
        elif vis == "public":
            entry["reason"] = "authenticated app is listed publicly"
        elif want != have:
            entry["reason"] = "landing requiredGroups differ from auth.groups"
        (offenders if "reason" in entry else consistent).append(entry)
    ev = {"consistent": consistent, "offenders": offenders}
    if not consistent and not offenders:
        return not_applicable("no authenticated NebariApp is on the landing page", **ev)
    if offenders:
        return failed(f"{len(offenders)} landing entr(ies) inconsistent: " + ", ".join(o["app"] for o in offenders),
                      **ev)
    return passed(f"{len(consistent)} landing entr(ies) restricted to their app's groups", **ev)
