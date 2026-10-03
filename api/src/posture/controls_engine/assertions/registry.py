"""Container registry assertion."""

from __future__ import annotations

from typing import Any

import httpx

from ..context import EngineContext
from ..model import Result, assertion, failed, not_applicable, passed, unknown

C = "container-registry"


def _host_port(ref: str) -> tuple[str, int | None, str | None]:
    scheme = None
    if "://" in ref:
        scheme, ref = ref.split("://", 1)
    ref = ref.split("/", 1)[0]
    host, _, port = ref.partition(":")
    return host, int(port) if port.isdigit() else None, scheme


def _backing_service(services: list[dict[str, Any]], host: str, port: int | None) -> dict[str, Any] | None:
    for svc in services:
        m, spec = svc["metadata"], svc.get("spec") or {}
        names = {f"{m['name']}.{m['namespace']}.svc.cluster.local", f"{m['name']}.{m['namespace']}.svc",
                 f"{m['name']}.{m['namespace']}", spec.get("clusterIP")}
        ports = [p.get("port") for p in spec.get("ports") or []] + [p.get("nodePort") for p in spec.get("ports") or []]
        if host in names and (port is None or port in ports):
            return svc
        if host in ("localhost", "127.0.0.1") and port in [p.get("nodePort") for p in spec.get("ports") or []]:
            return svc
    return None


@assertion(id="reg-access-restricted", title="Container registry requires auth or is cluster-internal only",
           controls=["CM-14", "SR-4"], component=C, severity="high")
async def registry_access(ctx: EngineContext) -> Result:
    """The registry's `/v2/` endpoint demands authentication (401), or it is reachable only inside
    the cluster: its Service is ClusterIP (no NodePort/LoadBalancer/externalIPs) and no HTTPRoute
    exposes it through the gateway. Read-only probe; nothing is pushed."""
    ref = ctx.config.registry_url
    if not ref:
        return not_applicable("no in-cluster registry configured (controlsEngine.registryUrl / MIRROR_REGISTRY)")
    host, port, scheme = _host_port(ref)
    base = f"{scheme or 'http'}://{host}" + (f":{port}" if port else "")
    try:
        r = await ctx.http_get(f"{base}/v2/")
    except httpx.HTTPError as e:
        return unknown(f"registry {base} unreachable: {type(e).__name__}", registry=base)
    ev: dict[str, Any] = {"registry": base, "v2Status": r.status_code,
                          "authenticate": r.headers.get("www-authenticate")}
    if r.status_code == 401:
        return passed(f"{base} requires authentication (HTTP 401)", **ev)
    if r.status_code != 200:
        return unknown(f"{base}/v2/ returned HTTP {r.status_code}", **ev)
    svc = _backing_service(await ctx.services(), host, port)
    exposures = []
    if svc is None:
        ev["service"] = None
        return failed(f"{base} accepts anonymous access and is not a cluster-internal Service", **ev)
    spec = svc.get("spec") or {}
    ev["service"] = f"{svc['metadata']['namespace']}/{svc['metadata']['name']}"
    ev["serviceType"] = spec.get("type", "ClusterIP")
    if spec.get("type") in ("NodePort", "LoadBalancer"):
        exposures.append(f"{spec['type']} " + ",".join(str(p.get("nodePort")) for p in spec.get("ports") or []
                                                        if p.get("nodePort")))
    if spec.get("externalIPs"):
        exposures.append("externalIPs " + ",".join(spec["externalIPs"]))
    routes = await ctx.k8s_list_optional("/apis/gateway.networking.k8s.io/v1/httproutes") or []
    for rt in routes:
        for rule in (rt.get("spec") or {}).get("rules") or []:
            for b in rule.get("backendRefs") or []:
                if b.get("name") == svc["metadata"]["name"] and \
                        b.get("namespace", rt["metadata"]["namespace"]) == svc["metadata"]["namespace"]:
                    exposures.append(f"HTTPRoute {rt['metadata']['namespace']}/{rt['metadata']['name']}")
    ev["exposures"] = exposures
    if exposures:
        return failed(f"anonymous registry {ev['service']} is exposed outside the cluster: " + "; ".join(exposures),
                      **ev)
    return passed(f"anonymous registry {ev['service']} is cluster-internal only (ClusterIP, no route)", **ev)
