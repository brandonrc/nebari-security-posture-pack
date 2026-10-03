"""Assertions about this pack's own continuous-monitoring evidence (from the latest scan snapshot)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..context import EngineContext, NotConfigured
from ..model import Result, assertion, failed, passed, unknown

C = "security-posture"


def _snap(ctx: EngineContext) -> dict[str, Any]:
    if ctx.snapshot is None:
        raise NotConfigured("scan evidence unavailable (posture database not readable)")
    return ctx.snapshot


def _full_scan(snap: dict[str, Any]) -> dict[str, Any] | None:
    """Latest done full scan; snapshots without the key (older callers, tests) use lastDoneScan."""
    return snap["lastFullScan"] if "lastFullScan" in snap else snap.get("lastDoneScan")


def _ts(v: Any) -> datetime | None:
    if v is None or isinstance(v, datetime):
        return v.replace(tzinfo=v.tzinfo or UTC) if v else None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_h(v: Any) -> float | None:
    t = _ts(v)
    return round((datetime.now(UTC) - t).total_seconds() / 3600, 1) if t else None


@assertion(id="pack-scan-recent", title="Vulnerability scan completed within 2x the scan interval",
           controls=["RA-5"],
           objectives=["ra-5_obj.a-2"], component=C, severity="high")
async def scan_recent(ctx: EngineContext) -> Result:
    """The latest completed full scan finished less than 2 x `scanIntervalHours` ago (targeted
    event / image rescans do not count)."""
    snap = _snap(ctx)
    last = _full_scan(snap)
    interval = float(snap.get("scanIntervalHours") or ctx.config.scan_interval_hours)
    if not last:
        return failed("no vulnerability scan has completed yet", scanIntervalHours=interval)
    age = _age_h(last.get("finishedAt"))
    ev = {"scanId": last.get("id"), "finishedAt": str(last.get("finishedAt")), "ageHours": age,
          "scanIntervalHours": interval, "imagesTotal": last.get("imagesTotal"), "score": last.get("score")}
    if age is None or age > 2 * interval:
        return failed(f"last completed scan {last.get('id')} is {age}h old (limit {2 * interval:g}h)", **ev)
    return passed(f"scan {last.get('id')} completed {age}h ago (limit {2 * interval:g}h)", **ev)


@assertion(id="pack-scanner-db-fresh", title="Scanner vulnerability databases are current",
           controls=["RA-5(2)"],
           objectives=["ra-5.2_obj"], component=C, severity="medium")
async def scanner_db_fresh(ctx: EngineContext) -> Result:
    """Every enabled scanner reports a vulnerability DB updated within 72 hours."""
    scanners = [s for s in _snap(ctx).get("scanners") or [] if s.get("enabled", True)]
    if not scanners:
        return unknown("no scanner status recorded yet")
    rows, stale = [], []
    for s in scanners:
        age = _age_h(s.get("dbUpdatedAt"))
        row = {"scanner": s.get("name"), "dbUpdatedAt": str(s.get("dbUpdatedAt")) if s.get("dbUpdatedAt") else None,
               "ageHours": age, "healthy": s.get("healthy")}
        rows.append(row)
        if age is None or age > ctx.config.freshness_hours:
            stale.append(row)
    ev = {"scanners": rows, "maxAgeHours": ctx.config.freshness_hours}
    if stale:
        return failed("stale or unknown DB: " + ", ".join(f"{r['scanner']} ({r['ageHours'] or '?'}h)" for r in stale),
                      **ev)
    return passed("DBs fresh: " + ", ".join(f"{r['scanner']} {r['ageHours']}h" for r in rows), **ev)


@assertion(id="pack-poam-current", title="A POA&M exists for the latest scan's open findings", controls=["CA-5"], objectives=["ca-5_obj.a"],
           component=C, severity="medium")
async def poam_current(ctx: EngineContext) -> Result:
    """When the latest full scan has open findings or failing checks, a POA&M report was generated
    from it (targeted event scans generate no reports)."""
    snap = _snap(ctx)
    last = _full_scan(snap)
    if not last:
        return unknown("no completed scan yet")
    open_items = int(snap.get("openFindings") or 0) + len(snap.get("postureFailures") or [])
    poam = snap.get("latestPoam")
    ev = {"scanId": last.get("id"), "openFindings": snap.get("openFindings"),
          "failingChecks": len(snap.get("postureFailures") or []), "latestPoam": poam}
    if open_items == 0:
        return passed("no open findings to track", **ev)
    if not poam:
        return failed(f"{open_items} open item(s) but no POA&M has been generated "
                      "(add 'poam' to settings reports.autoGenerate)", **ev)
    # A POA&M generated after the full scan (e.g. on demand while a later event scan was the
    # newest) covers the same or newer findings; scan ids increase monotonically.
    if not isinstance(poam.get("scanId"), int) or poam["scanId"] < int(last.get("id") or 0):
        return failed(f"latest POA&M is from scan {poam.get('scanId')}, latest full scan is {last.get('id')}", **ev)
    return passed(f"POA&M {poam.get('id')} generated from scan {poam.get('scanId')} "
                  f"(latest full scan {last.get('id')})", **ev)


@assertion(id="pack-sla-overdue", title="No findings past their remediation SLA", controls=["SI-2"], objectives=["si-2_obj.a-3", "si-2_obj.c-1"], component=C,
           severity="high")
async def sla_overdue(ctx: EngineContext) -> Result:
    """Count of open consensus findings on running images past `firstSeen + SLA(severity)` is zero."""
    snap = _snap(ctx)
    if not snap.get("lastDoneScan"):
        return unknown("no completed scan yet")
    if snap.get("slaOverdue") is None:  # absent evidence is not "zero overdue"
        return unknown("SLA overdue counts unavailable for the latest scan")
    od = {k: int(v) for k, v in (snap.get("slaOverdue") or {}).items()}
    total = sum(od.values())
    ev = {"slaOverdue": od, "slaDays": snap.get("slaDays")}
    if total:
        return failed(f"{total} finding(s) past SLA (" + ", ".join(f"{k} {v}" for k, v in od.items() if v) + ")", **ev)
    return passed("no findings past their remediation SLA", **ev)


@assertion(id="pack-inventory-current", title="Component inventory refreshed by the latest scan", controls=["CM-8"], objectives=["cm-8_obj.a.1", "cm-8_obj.a.2", "cm-8_obj.b"],
           component=C, severity="medium")
async def inventory_current(ctx: EngineContext) -> Result:
    """The latest completed scan captured a complete inventory less than 2 x `scanIntervalHours` ago."""
    snap = _snap(ctx)
    last = snap.get("lastDoneScan")
    interval = float(snap.get("scanIntervalHours") or ctx.config.scan_interval_hours)
    if not last:
        return failed("no inventory has been captured yet")
    age = _age_h(last.get("finishedAt"))
    inv = snap.get("inventory") or {}
    ev = {"scanId": last.get("id"), "ageHours": age, "inventoryComplete": last.get("inventoryComplete"), **inv}
    if not last.get("inventoryComplete"):
        return failed(f"scan {last.get('id')} inventory incomplete", **ev)
    if age is None or age > 2 * interval:
        return failed(f"inventory is {age}h old (limit {2 * interval:g}h)", **ev)
    return passed(f"inventory of {inv.get('containers', '?')} container(s) / {inv.get('images', '?')} image(s) "
                  f"captured {age}h ago", **ev)
