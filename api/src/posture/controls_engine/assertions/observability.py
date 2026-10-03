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
           controls=["AU-12"],
           objectives=["au-12_obj.c"], component=LOKI, severity="high")
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
           controls=["AU-4", "AU-11"], objectives=["au-4_obj", "au-11_obj"], component=LOKI, severity="medium")
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
           controls=["SI-4", "CA-7"],
           objectives=["si-4_obj.c.1", "ca-7_obj.d"], component=PROM, severity="medium")
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


SECURITY_RULE = re.compile(r"secur|auth|login|logon|brute|intrus|anomal|unauthori[sz]|privileg|falco|tetragon|audit|"
                           r"attack|malware|exploit|suspicious|cert(ificate)?expir|kev|cve", re.I)
LOG_PIPELINE_RULE = re.compile(r"(loki|promtail|alloy|fluent|vector|logging|log[-_ ]?pipeline)", re.I)
LOG_FAILURE_RULE = re.compile(r"(fail|error|drop|discard|down|absent|unhealthy|lag|reject|backpressure|request)", re.I)


async def alert_rules(ctx: EngineContext) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Alerting rules loaded in Prometheus (`/api/v1/rules?type=alert`): [{name, group, labels}]."""
    async def fetch() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        rules, errors = [], []
        for u in await prometheus_urls(ctx):
            try:
                r = await ctx.http_get(f"{u}/api/v1/rules", params={"type": "alert"})
                if r.status_code != 200:
                    raise ValueError(f"HTTP {r.status_code}")
                for g in ((r.json() or {}).get("data") or {}).get("groups") or []:
                    for rule in g.get("rules") or []:
                        if rule.get("type", "alerting") == "alerting":
                            rules.append({"name": rule.get("name"), "group": g.get("name"),
                                          "labels": rule.get("labels") or {}})
            except (httpx.HTTPError, ValueError) as e:
                errors.append({"url": u, "error": _err(e)})
        return rules, errors

    return await ctx.memo("prometheus:alert-rules", fetch)


def _rule_text(r: dict[str, Any]) -> str:
    return " ".join([str(r.get("name") or ""), str(r.get("group") or ""),
                     *(f"{k}={v}" for k, v in (r.get("labels") or {}).items())])


@assertion(id="log-pipeline-alerting", title="Log pipeline failures raise an alert",
           controls=["AU-5"], objectives=["au-5_obj.a"], component=LOKI, severity="medium")
async def log_pipeline_alerting(ctx: EngineContext) -> Result:
    """Prometheus has at least one alerting rule for a failure of the log pipeline (Loki / Promtail /
    Alloy errors, dropped or rejected entries), so a stop in audit logging reaches someone (AU-5 a)."""
    if not await prometheus_urls(ctx):
        return failed("no Prometheus service found: log pipeline failures cannot alert")
    rules, errors = await alert_rules(ctx)
    if not rules and errors:
        return unknown("Prometheus rules unreachable: " + "; ".join(e["error"] for e in errors), errors=errors)
    hits = [r for r in rules if LOG_PIPELINE_RULE.search(_rule_text(r)) and LOG_FAILURE_RULE.search(_rule_text(r))]
    ev = {"alertRules": len(rules), "logPipelineRules": [r["name"] for r in hits][:50], "errors": errors}
    if not hits:
        return failed(f"none of {len(rules)} alerting rule(s) covers a log pipeline failure", **ev)
    return passed(f"{len(hits)} alerting rule(s) for log pipeline failures: " + ", ".join(ev["logPipelineRules"][:5]),
                  **ev)


def receivers_with_integrations(config_yaml: str) -> tuple[list[str], list[str]]:
    cfg = yaml.safe_load(config_yaml or "") or {}
    active, empty = [], []
    for r in cfg.get("receivers") or []:
        has = any(k.endswith("_configs") and v for k, v in r.items())
        (active if has else empty).append(r.get("name"))
    return active, empty


@assertion(id="mon-alert-receivers", title="Security alert rules notify a receiver",
           controls=["SI-4(5)", "IR-6(1)"],
           objectives=["si-4.5_obj", "ir-6.1_obj"], component=PROM, severity="high")
async def alert_receivers(ctx: EngineContext) -> Result:
    """Alertmanager's loaded configuration has at least one receiver with an integration
    (email/slack/webhook/pagerduty/...) and Prometheus has at least one security-relevant alerting
    rule (authentication, intrusion, privilege, audit, runtime detection...). A receiver without
    security alert rules does not alert anyone about attacks (SI-4(5), compliance review M4)."""
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
    ev: dict[str, Any] = {"instances": rows, "errors": errors}
    if not good:
        return failed("Alertmanager has no receiver with a notification integration (only: "
                      + ", ".join(sorted({n for r in rows for n in r["emptyReceivers"] if n})) + ")", **ev)
    receivers = ", ".join(n for r in good for n in r["receivers"])
    rules, rule_errors = await alert_rules(ctx) if await prometheus_urls(ctx) else ([], [])
    security = [r["name"] for r in rules if SECURITY_RULE.search(_rule_text(r))]
    ev.update(alertRules=len(rules), securityRules=security[:50], ruleErrors=rule_errors)
    if not rules and rule_errors:
        return unknown(f"receivers {receivers}; Prometheus alert rules unreachable", **ev)
    if not security:
        return failed(f"receivers {receivers}, but none of {len(rules)} alerting rule(s) is security-relevant", **ev)
    return passed(f"receivers {receivers}; {len(security)} security alert rule(s): " + ", ".join(security[:5]), **ev)
