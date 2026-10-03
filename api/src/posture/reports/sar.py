"""Security Assessment Report (SAR): Jinja2 HTML -> PDF (WeasyPrint)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ._common import (CONTROL_TITLES, SCANNER_TITLES, SEVERITIES, SYSTEM_NAMESPACES, TOOL_NAME, View, filename,
                      image_label, normalize, sev_rank)
from .registry import GeneratedReport, ReportDependencyMissing

TEMPLATES = Path(__file__).parent / "templates"
APPENDIX_FINDINGS_MAX = 2000
FRESHNESS_HOURS = 72


def _env():
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["dt"] = lambda d, fmt="%Y-%m-%d %H:%M UTC": d.strftime(fmt) if d else "-"
    env.filters["num"] = lambda x, nd=1: "-" if x is None else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))
    env.filters["pct"] = lambda x: "-" if x is None else f"{x * 100:.0f}%"
    env.filters["shortdigest"] = lambda d: (d.split(":", 1)[-1][:12] if d else "-")
    return env


def _grade_class(g: str) -> str:
    return {"A": "g-a", "B": "g-b", "C": "g-c", "D": "g-d", "F": "g-f"}.get((g or "?")[:1], "g-u")


def _trend_svg(v: View) -> dict[str, Any] | None:
    pts = [t for t in v.trend if t.score is not None]
    if len(pts) < 2:
        return None
    w, h, pad = 640.0, 140.0, 18.0
    n = len(pts)
    scores = [max(0.0, min(100.0, float(t.score))) for t in pts]
    lo = max(0.0, (min(scores) // 10) * 10 - 10)  # zoom the y axis to the data, in 10-point steps
    hi = min(100.0, (max(scores) // 10) * 10 + 10)

    def y_of(s: float) -> float:
        return round(pad + (h - 2 * pad) * (1 - (s - lo) / (hi - lo)), 1)

    xy = [(round(pad + (w - 2 * pad) * idx / (n - 1), 1), y_of(s)) for idx, s in enumerate(scores)]
    line = " ".join(f"{x},{y}" for x, y in xy)
    area = f"{xy[0][0]},{h - pad} " + line + f" {xy[-1][0]},{h - pad}"
    grid = [{"y": y_of(g), "label": f"{g:g}"} for g in sorted({lo, hi, 50.0, 65.0, 80.0, 90.0}) if lo <= g <= hi]
    return {"w": w, "h": h, "line": line, "area": area, "grid": grid, "last": xy[-1], "first": pts[0],
            "final": pts[-1], "points": pts}


def _cve_rows(v: View) -> list[SimpleNamespace]:
    by: dict[str, list] = {}
    for f in v.open_findings:
        by.setdefault(f.vuln_id, []).append(f)
    n_enabled = len([s for s in v.scanners if s.enabled]) or 3
    rows = []
    for vid, fs in by.items():
        f0 = max(fs, key=lambda f: sev_rank(f.severity))
        first = min(f.first_seen_at for f in fs)
        scanners = sorted({s for f in fs for s in f.scanners})
        rows.append(SimpleNamespace(
            vuln_id=vid, severity=f0.severity, title=f0.title, url=f0.url, cvss=f0.cvss,
            packages=sorted({f.package for f in fs}), images=len({f.image_id for f in fs}),
            scanners=scanners, agreement=f"{len(scanners)}/{n_enabled}", fixable=all(f.fixable for f in fs),
            fixed=sorted({f.fixed_version for f in fs if f.fixed_version}), due=v.sla_due(f0.severity, first),
            overdue=v.overdue(f0.severity, first), first_seen=first,
        ))
    rows.sort(key=lambda r: (-sev_rank(r.severity), not r.overdue, -r.images, r.vuln_id))
    return rows


def context(v: View) -> dict[str, Any]:
    from .stig import rules_for_check

    counts = v.severity_counts()
    fixable = v.severity_counts(f for f in v.open_findings if f.fixable)
    overdue = {s: 0 for s in SEVERITIES}
    for f in v.open_findings:
        if v.overdue(f.severity, f.first_seen_at):
            overdue[f.severity] += 1
    n_enabled = len([s for s in v.scanners if s.enabled]) or 3
    agreement = {k: 0 for k in range(1, n_enabled + 1)}
    for f in v.open_findings:
        k = max(1, min(n_enabled, len(f.scanners) or 1))
        agreement[k] = agreement.get(k, 0) + 1

    scanners = []
    warnings = []
    for s in v.scanners:
        age_h = (v.now - s.db_updated_at).total_seconds() / 3600 if s.db_updated_at else None
        stale = age_h is not None and age_h > FRESHNESS_HOURS
        if stale:
            warnings.append(f"{SCANNER_TITLES.get(s.name, s.name)} database is {age_h / 24:.1f} days old.")
        if s.enabled and not s.healthy:
            warnings.append(f"{SCANNER_TITLES.get(s.name, s.name)} was unhealthy: {s.last_error or 'unknown error'}.")
        scanners.append(SimpleNamespace(**vars(s), title=SCANNER_TITLES.get(s.name, s.name),
                                        age_days=None if age_h is None else age_h / 24, stale=stale))

    failed_images = [i for i in v.images if i.score is None]
    checks = []
    for c in sorted({r.check_id for r in v.posture_results} | {c.id for c in v.checks},
                    key=lambda cid: (-sev_rank(v.check(cid).severity), cid)):
        chk = v.check(c)
        rs = [r for r in v.posture_results if r.check_id == c]
        failed = [r for r in rs if r.status == "fail"]
        passed = [r for r in rs if r.status == "pass"]
        checks.append(SimpleNamespace(
            id=c, title=chk.title, severity=chk.severity, controls=chk.controls, remediation=chk.remediation,
            description=chk.description, passed=len(passed) if rs else chk.passed,
            failed=len(failed) if rs else chk.failed, offenders=sorted({r.key for r in failed}),
            system_only=bool(failed) and all(r.system_namespace for r in failed),
            stig=[r["vulnId"] for r in rules_for_check(c)],
        ))

    controls: dict[str, SimpleNamespace] = {}
    for f in v.open_findings:
        for c in f.controls:
            controls.setdefault(c, SimpleNamespace(id=c, title=CONTROL_TITLES.get(c, ""), findings=0, checks=0))
            controls[c].findings += 1
    for ch in checks:
        if ch.failed:
            for c in ch.controls:
                controls.setdefault(c, SimpleNamespace(id=c, title=CONTROL_TITLES.get(c, ""), findings=0, checks=0))
                controls[c].checks += 1

    stig = stig_summary(v)
    in_b = [s for s in v.engine_statuses if s.get("inBaseline", True)]
    engine_counts = []
    if in_b:
        from ..controls_engine.engine import CONTROL_STATUSES

        engine_counts = [(st, sum(s.get("status") == st for s in in_b)) for st in CONTROL_STATUSES]
    cve_rows = _cve_rows(v)
    appendix = sorted(v.open_findings, key=lambda f: (-sev_rank(f.severity), f.vuln_id, str(f.image_id)))
    img_refs = {i.id: i for i in v.images}
    return {
        "v": v,
        "tool": TOOL_NAME,
        "system": v.system,
        "scan": v.scan,
        "scope_label": v.scope_label,
        "generated_at": v.generated_at,
        "grade_class": _grade_class(v.scan.grade),
        "severities": SEVERITIES,
        "counts": counts,
        "fixable": fixable,
        "overdue": overdue,
        "total_open": sum(counts.values()),
        "agreement": agreement,
        "n_enabled": n_enabled,
        "scanners": scanners,
        "warnings": warnings,
        "trend": _trend_svg(v),
        "images": sorted(v.images, key=lambda i: (i.score if i.score is not None else 101, i.ref)),
        "failed_images": failed_images,
        "image_label": image_label,
        "img_refs": img_refs,
        "workloads": v.workloads,
        "namespaces": v.namespaces,
        "cve_rows": cve_rows,
        "top_cves": [r for r in cve_rows if r.severity in ("critical", "high")][:60],
        "checks": checks,
        "controls": sorted(controls.values(), key=lambda c: c.id),
        "stig": stig,
        "engine_run": v.engine_run,
        "engine_counts": engine_counts,
        "engine_baseline": v.engine.get("baseline") or v.engine_run.get("baseline") or "selected",
        "appendix": appendix[:APPENDIX_FINDINGS_MAX],
        "appendix_truncated": max(0, len(appendix) - APPENDIX_FINDINGS_MAX),
        "sla_days": v.sla_days,
        "system_namespaces": sorted(SYSTEM_NAMESPACES),
        "grade_class_fn": _grade_class,
        "logo_svg": (TEMPLATES / "nebari-logo.svg").read_text(encoding="utf-8").split("?>", 1)[-1],
        "freshness_hours": FRESHNESS_HOURS,
        "include_system": v.options.get("includeSystemNamespaces", True),
    }


def stig_summary(v: View) -> dict[str, Any]:
    from .stig import _selected_rules, evaluate_rule

    by_status: dict[str, dict[str, int]] = {}
    open_rules = []
    for r in _selected_rules(v):
        e = evaluate_rule(r, v)
        by_status.setdefault(e.status, {"I": 0, "II": 0, "III": 0})
        by_status[e.status][r["cat"]] += 1
        if e.status == "Open":
            open_rules.append(SimpleNamespace(vuln_id=r["vulnId"], cat=r["cat"], title=r["ruleTitle"],
                                              benchmark=r["benchmark"], offenders=len(e.offenders)))
    return {"by_status": by_status, "open": open_rules}


def render_html(v: View) -> str:
    return _env().get_template("sar.html.j2").render(**context(v))


def html_to_pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:  # OSError: missing pango/harfbuzz shared libraries
        raise ReportDependencyMissing(
            "PDF rendering needs WeasyPrint and its system libraries "
            "(apt-get install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 fonts-dejavu-core): " + str(exc).splitlines()[0]
        ) from exc
    return HTML(string=html, base_url=str(TEMPLATES)).write_pdf()


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    html = render_html(v)
    if fmt == "html":
        return GeneratedReport(html.encode("utf-8"), filename(v, "sar", "html"), "text/html; charset=utf-8")
    return GeneratedReport(html_to_pdf(html), filename(v, "sar", "pdf"), "application/pdf")
