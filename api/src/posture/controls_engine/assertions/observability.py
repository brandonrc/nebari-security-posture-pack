"""Logging (Loki) and monitoring (Prometheus / Alertmanager) assertions."""

from __future__ import annotations

import re
from typing import Any

import httpx
import yaml

from ..context import EngineContext
from ..model import Result, assertion, failed, passed, unknown

LOKI = "loki"
PROM = "prometheus"
NS_LABELS = ("namespace", "k8s_namespace_name", "service_namespace")
_DUR = re.compile(r"(\d+(?:\.\d+)?)(ms|y|w|d|h|m|s)")
_UNIT = {"y": 365 * 86400, "w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def parse_duration(v: Any) -> float | None:
    """Prometheus/Loki duration (`744h`, `31d`, `2160h0m0s`, `0s`) -> seconds."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    parts = _DUR.findall(s)
    if not parts or "".join(n + u for n, u in parts) != s:
        return None
    return sum(float(n) * _UNIT[u] for n, u in parts)


def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {e}"[:200]


async def loki_urls(ctx: EngineContext) -> list[str]:
    if ctx.config.loki_url:
        return [u.strip().rstrip("/") for u in ctx.config.loki_url.split(",") if u.strip()]

    def match(svc: dict[str, Any], port: dict[str, Any]) -> bool:
        name = svc["metadata"]["name"]
        if "loki" not in name or any(x in name for x in ("canary", "memberlist", "headless")):
            return False
        return port.get("port") == 3100 or ("gateway" in name and port.get("port") == 80)

    return await ctx.discover_service_url("loki", match)


async def prometheus_urls(ctx: EngineContext) -> list[str]:
    if ctx.config.prometheus_url:
        return [ctx.config.prometheus_url.rstrip("/")]
    return await ctx.discover_service_url(
        "prometheus", lambda s, p: "prometheus" in s["metadata"]["name"] and p.get("port") == 9090
        and "operator" not in s["metadata"]["name"])


async def alertmanager_urls(ctx: EngineContext) -> list[str]:
    if ctx.config.alertmanager_url:
        return [ctx.config.alertmanager_url.rstrip("/")]
    return await ctx.discover_service_url(
        "alertmanager", lambda s, p: "alertmanager" in s["metadata"]["name"] and p.get("port") == 9093)


async def _loki_namespaces(ctx: EngineContext, url: str) -> tuple[set[str] | None, str | None]:
    since = f"{ctx.config.log_window_minutes}m"
    for label in NS_LABELS:
        try:
            r = await ctx.http_get(f"{url}/loki/api/v1/label/{label}/values", params={"since": since})
        except httpx.HTTPError as e:
            return None, _err(e)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        vals = set((r.json() or {}).get("data") or [])
        if vals:
            return vals, label
    return set(), None


@assertion(id="log-ingest-all-namespaces", title="Logs from every namespace reach Loki",
           controls=["AU-2", "AU-6", "AU-12"], component=LOKI, severity="high")
async def log_ingest(ctx: EngineContext) -> Result:
    """Every namespace with running pods has log streams in Loki within the last
    `controlsEngine.logWindowMinutes` (default 10) minutes (union over discovered Loki instances)."""
    urls = await loki_urls(ctx)
    if not urls:
        return failed("no Loki service found (set controlsEngine.lokiUrl)")
    running = sorted({p["metadata"]["namespace"] for p in await ctx.pods()
                      if (p.get("status") or {}).get("phase") == "Running"})
    seen: set[str] = set()
    instances = []
    for u in urls:
        vals, info = await _loki_namespaces(ctx, u)
        if vals is None:
            instances.append({"url": u, "error": info})
            continue
        seen |= vals
        instances.append({"url": u, "label": info, "namespaces": len(vals),
                          "missing": sorted(set(running) - vals)})
    if not any("error" not in i for i in instances):
        return unknown("Loki unreachable: " + "; ".join(f"{i['url']}: {i['error']}" for i in instances),
                       instances=instances)
    missing = sorted(set(running) - seen)
    ev = {"windowMinutes": ctx.config.log_window_minutes, "runningNamespaces": len(running), "missing": missing,
          "instances": instances}
    if missing:
        return failed(f"{len(missing)} of {len(running)} namespace(s) with running pods sent no logs in "
                      f"{ctx.config.log_window_minutes}m: " + ", ".join(missing[:12]), **ev)
    return passed(f"logs from all {len(running)} running namespace(s) in the last {ctx.config.log_window_minutes}m",
                  **ev)


def loki_retention(cfg: dict[str, Any]) -> dict[str, Any]:
    limits = cfg.get("limits_config") or {}
    compactor = cfg.get("compactor") or {}
    table = cfg.get("table_manager") or {}
    period = parse_duration(limits.get("retention_period"))
    enabled = bool(compactor.get("retention_enabled")) or bool(table.get("retention_deletes_enabled"))
    if enabled and not period:
        period = parse_duration(table.get("retention_period"))
    return {"retentionEnabled": enabled, "retentionPeriod": limits.get("retention_period"),
            "retentionDays": round(period / 86400, 1) if enabled and period else None,
            "unbounded": not enabled or not period}


@assertion(id="log-retention", title="Log retention meets the organization-defined period",
           controls=["AU-4", "AU-11"], component=LOKI, severity="medium")
async def log_retention(ctx: EngineContext) -> Result:
    """Each Loki instance either deletes nothing (retention disabled: bounded only by storage) or keeps
    logs for at least `controlsEngine.minLogRetentionDays` (read from Loki `/config`)."""
    urls = await loki_urls(ctx)
    if not urls:
        return failed("no Loki service found (set controlsEngine.lokiUrl)")
    rows, bad, errors = [], [], []
    for u in urls:
        try:
            r = await ctx.http_get(f"{u}/config")
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            info = loki_retention(yaml.safe_load(r.text) or {})
        except (httpx.HTTPError, ValueError, yaml.YAMLError) as e:
            errors.append({"url": u, "error": _err(e)})
            continue
        info["url"] = u
        rows.append(info)
        if not info["unbounded"] and (info["retentionDays"] or 0) < ctx.config.min_log_retention_days:
            bad.append(info)
    ev = {"minDays": ctx.config.min_log_retention_days, "instances": rows, "errors": errors}
    if not rows:
        return unknown("Loki /config unreachable: " + "; ".join(e["error"] for e in errors), **ev)
    if bad:
        return failed("retention below policy: " + ", ".join(f"{b['url']} keeps {b['retentionDays']}d" for b in bad)
                      + f" (< {ctx.config.min_log_retention_days}d)", **ev)
    return passed("; ".join(f"{r['url']}: " + ("no deletion (bounded by storage)" if r["unbounded"]
                                               else f"{r['retentionDays']}d") for r in rows), **ev)


@assertion(id="mon-prometheus-scraping", title="Prometheus is scraping platform targets",
           controls=["AU-6", "SI-4"], component=PROM, severity="medium")
async def prometheus_scraping(ctx: EngineContext) -> Result:
    """A Prometheus instance has active scrape targets that are up (`/api/v1/targets`)."""
    urls = await prometheus_urls(ctx)
    if not urls:
        return failed("no Prometheus service found (set controlsEngine.prometheusUrl)")
    instances, errors = [], []
    for u in urls:
        try:
            r = await ctx.http_get(f"{u}/api/v1/targets", params={"state": "active"})
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            targets = ((r.json() or {}).get("data") or {}).get("activeTargets") or []
        except (httpx.HTTPError, ValueError) as e:
            errors.append({"url": u, "error": _err(e)})
            continue
        jobs: dict[str, dict[str, int]] = {}
        for t in targets:
            job = (t.get("labels") or {}).get("job") or (t.get("discoveredLabels") or {}).get("job") or "?"
            j = jobs.setdefault(job, {"up": 0, "down": 0})
            j["up" if t.get("health") == "up" else "down"] += 1
        up = sum(j["up"] for j in jobs.values())
        instances.append({"url": u, "targets": len(targets), "up": up, "jobs": jobs})
    if not instances:
        return unknown("Prometheus unreachable: " + "; ".join(e["error"] for e in errors), errors=errors)
    best = max(instances, key=lambda i: i["up"])
    ev = {"instances": instances, "errors": errors}
    if best["up"] == 0:
        return failed("Prometheus has no healthy scrape targets", **ev)
    down = sum(j["down"] for j in best["jobs"].values())
    return passed(f"{best['up']}/{best['targets']} targets up across {len(best['jobs'])} job(s) at {best['url']}"
                  + (f" ({down} down)" if down else ""), **ev)


def receivers_with_integrations(config_yaml: str) -> tuple[list[str], list[str]]:
    cfg = yaml.safe_load(config_yaml or "") or {}
    active, empty = [], []
    for r in cfg.get("receivers") or []:
        has = any(k.endswith("_configs") and v for k, v in r.items())
        (active if has else empty).append(r.get("name"))
    return active, empty


@assertion(id="mon-alert-receivers", title="Alertmanager notifies at least one receiver",
           controls=["SI-4(5)", "IR-6"], component=PROM, severity="high")
async def alert_receivers(ctx: EngineContext) -> Result:
    """Alertmanager's loaded configuration has at least one receiver with an integration
    (email/slack/webhook/pagerduty/...), i.e. alerts reach a person."""
    urls = await alertmanager_urls(ctx)
    if not urls:
        return failed("no Alertmanager service found (set controlsEngine.alertmanagerUrl)")
    rows, errors = [], []
    for u in urls:
        try:
            r = await ctx.http_get(f"{u}/api/v2/status")
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            active, empty = receivers_with_integrations(((r.json() or {}).get("config") or {}).get("original", ""))
        except (httpx.HTTPError, ValueError, yaml.YAMLError) as e:
            errors.append({"url": u, "error": _err(e)})
            continue
        rows.append({"url": u, "receivers": active, "emptyReceivers": empty})
    if not rows:
        return unknown("Alertmanager unreachable: " + "; ".join(e["error"] for e in errors), errors=errors)
    good = [r for r in rows if r["receivers"]]
    ev = {"instances": rows, "errors": errors}
    if not good:
        return failed("Alertmanager has no receiver with a notification integration (only: "
                      + ", ".join(sorted({n for r in rows for n in r["emptyReceivers"] if n})) + ")", **ev)
    return passed("alert receivers: " + ", ".join(n for r in good for n in r["receivers"]), **ev)
