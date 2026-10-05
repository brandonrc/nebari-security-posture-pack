"""Shared helpers for the compliance report generators.

`normalize(snapshot, options)` turns any object satisfying models_contract.md (pydantic
model, dataclass, dicts...) into a `View`: plain `SimpleNamespace` records with every
optional field defaulted and the scope / system-namespace filters applied. Generators
work only on the View, so they never care what the concrete snapshot type is.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from types import SimpleNamespace
from typing import Any, Iterable

SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
SEV_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}  # critical=6 .. unknown=1
DEFAULT_SLA_DAYS = {"critical": 15, "high": 30, "medium": 90, "low": 180, "negligible": 365, "unknown": 180}
from ..scoring import SYSTEM_NAMESPACES  # noqa: E402  (single source, S4)
SCANNERS = ("trivy", "grype", "clair")
SCANNER_TITLES = {"trivy": "Trivy", "grype": "Grype", "clair": "Clair"}
TOOL_NAME = "Nebari Security Posture Pack"

# NIST 800-53 tagging per DESIGN.md §11: data/controls.yaml is the only source (compliance review
# M4 removed the duplicated table that used to live here).
def _controls_yaml() -> dict[str, Any]:
    from ..controls import load_controls

    return load_controls()


CHECK_CONTROLS: dict[str, list[str]] = {str(k): list(v or []) for k, v in
                                        (_controls_yaml().get("checks") or {}).items()}
CONTROL_TITLES: dict[str, str] = {str(k): str(v) for k, v in (_controls_yaml().get("titles") or {}).items()}


def control_title(control: str) -> str:
    """Title from controls.yaml, else the vendored NIST catalog."""
    if control in CONTROL_TITLES:
        return CONTROL_TITLES[control]
    try:
        from ..controls_engine.catalog import get_catalog

        return get_catalog().title(control) or ""
    except Exception:  # noqa: BLE001
        return ""


_CCI_RE = re.compile(r"^\s*([A-Z]{2}-\d+)(?:\s*\((\d+)\))?")


@lru_cache(maxsize=1)
def _cci_map() -> dict[str, list[str]]:
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent / "data" / "cci_rev5.json").read_text(encoding="utf-8"))["cci"]


def cci_controls(ccis: Iterable[str]) -> list[str]:
    """DISA CCI -> NIST SP 800-53 rev5 controls (label form) from the vendored DISA CCI list (N1):
    `CCI-002233` -> `AC-6(8)`, `CCI-002605` -> `SI-2` (part c)."""
    out: list[str] = []
    for cci in ccis:
        for ref in _cci_map().get(cci, []):
            m = _CCI_RE.match(ref)
            if m:
                label = m.group(1) + (f"({int(m.group(2))})" if m.group(2) else "")
                if label not in out:
                    out.append(label)
    return out


def in_baseline(control: str, baseline: str) -> bool:
    """Membership of a control in the selected baseline / profile (vendored NIST + extra profiles)."""
    from ..controls_engine.catalog import get_catalog

    c = get_catalog().get(control)
    return bool(c and c.in_baseline(baseline))


def check_controls(check_id: str) -> list[str]:
    """Controls of a posture check; [] = operational hygiene only (no control, no POA&M row)."""
    return list(CHECK_CONTROLS.get(check_id, []))


CHECK_DEFAULTS: dict[str, tuple[str, str]] = {
    # id: (severity, title) - SCORING.md table, used when the snapshot omits `checks`.
    "privileged": ("critical", "Privileged container"),
    "host-namespaces": ("critical", "Pod shares host PID/IPC/network namespace"),
    "host-path": ("high", "Pod mounts a hostPath volume"),
    "run-as-root": ("high", "Container may run as root"),
    "privilege-escalation": ("high", "allowPrivilegeEscalation not disabled"),
    "added-capabilities": ("high", "Linux capabilities added"),
    "capabilities-not-dropped": ("medium", "Capabilities not dropped (ALL)"),
    "writable-rootfs": ("medium", "Root filesystem is writable"),
    "no-resource-limits": ("medium", "CPU/memory limits unset"),
    "no-resource-requests": ("low", "CPU/memory requests unset"),
    "mutable-tag": ("medium", "Image referenced by mutable tag"),
    "no-liveness-probe": ("low", "No liveness probe"),
    "no-readiness-probe": ("low", "No readiness probe"),
    "automount-sa-token": ("low", "Default ServiceAccount token automounted"),
    "seccomp-unconfined": ("medium", "Seccomp profile unconfined or unset"),
    "no-netpol": ("low", "No NetworkPolicy selects the pod"),
}


# --------------------------------------------------------------------------- access
def get(obj: Any, name: str, default: Any = None) -> Any:
    """getattr that also understands dicts (snake_case or camelCase keys)."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        if name in obj:
            v = obj[name]
        else:
            v = obj.get(_camel(name), default)
    else:
        v = getattr(obj, name, default)
    return default if v is None else v


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def as_dt(v: Any) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    if isinstance(v, str):
        s = v.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise TypeError(f"not a datetime: {v!r}")


def sev(v: Any) -> str:
    s = str(v or "unknown").strip().lower()
    return {"moderate": "medium", "important": "high", "info": "negligible"}.get(s, s if s in SEV_RANK else "unknown")


def sev_rank(s: str) -> int:
    return SEV_RANK.get(s, 0)


def iso(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def ymd(dt: datetime | date | None) -> str:
    return dt.strftime("%Y-%m-%d") if dt else ""


def mdy(dt: datetime | date | None) -> str:
    return dt.strftime("%m/%d/%Y") if dt else ""


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s or "").strip("-").lower() or "system"


NO_CCI_NOTE = ("No CCI: the SCAP content carries none for this rule and no DISA benchmark on the content "
               "volume maps its STIG id (SSG content; see scap_content).")


def short_hash(*parts: Any, n: int = 8) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:n]


def image_label(img: Any) -> str:
    """`ref@digest` (digest omitted when already pinned in ref or unknown)."""
    ref = img.ref
    if img.digest and "@" not in ref:
        return f"{ref}@{img.digest}"
    return ref


def workload_key(ns: str, kind: str, name: str) -> str:
    return f"{ns}/{kind}/{name}"


# --------------------------------------------------------------------------- view
@dataclass
class View:
    generated_at: datetime
    now: datetime
    system: SimpleNamespace
    scan: SimpleNamespace
    scope: SimpleNamespace
    sla_days: dict[str, int]
    scanners: list[SimpleNamespace]
    images: list[SimpleNamespace]
    findings: list[SimpleNamespace]
    workloads: list[SimpleNamespace]
    namespaces: list[SimpleNamespace]
    checks: list[SimpleNamespace]
    posture_results: list[SimpleNamespace]
    trend: list[SimpleNamespace]
    options: dict[str, Any]
    images_by_id: dict[Any, SimpleNamespace] = field(default_factory=dict)
    checks_by_id: dict[str, SimpleNamespace] = field(default_factory=dict)
    # control evidence engine run attached to the snapshot (M3: every report of a scan uses the same run)
    engine: dict[str, Any] = field(default_factory=dict)
    # DESIGN §14: OpenSCAP results per (image, benchmark) of the images in scope
    stig_benchmarks: list[SimpleNamespace] = field(default_factory=list)

    @property
    def stig_evaluated(self) -> list[SimpleNamespace]:
        return [b for b in self.stig_benchmarks if b.status == "evaluated" and b.benchmark_key]

    @property
    def stig_failures(self) -> list[tuple[SimpleNamespace, SimpleNamespace]]:
        """(benchmark, rule) for every failing product / OS STIG rule in scope."""
        return [(b, r) for b in self.stig_evaluated for r in b.rules if r.result == "fail"]

    @property
    def engine_run(self) -> dict[str, Any]:
        return (self.engine.get("data") or {}).get("run") or {}

    @property
    def engine_results(self) -> list[dict[str, Any]]:
        return list((self.engine.get("data") or {}).get("results") or [])

    @property
    def engine_statuses(self) -> list[dict[str, Any]]:
        return list((self.engine.get("data") or {}).get("statuses") or [])

    @property
    def run_stamp(self) -> str:
        """`scan <id> / control evidence run <id>` printed on every artifact (M3)."""
        run = self.engine_run.get("id")
        return f"scan {self.scan.id}" + (f" / control evidence run {run}" if run else " / no control evidence run")

    # ---- derived helpers
    def sla_due(self, severity: str, first_seen: datetime | None) -> datetime | None:
        base = first_seen or self.scan.started_at or self.generated_at
        return base + timedelta(days=self.sla_days.get(severity, DEFAULT_SLA_DAYS["unknown"])) if base else None

    def finding_due(self, f: SimpleNamespace) -> datetime | None:
        """Due date of a finding: the severity SLA from first seen, or the CISA KEV due date when it is
        earlier (BOD 22-01; option `kevDueDates`, default on)."""
        due = self.sla_due(f.severity, f.first_seen_at)
        kev = getattr(f, "kev_due", None)
        if kev and self.options.get("kevDueDates", True) and (due is None or kev < due):
            return kev
        return due

    def finding_overdue(self, f: SimpleNamespace) -> bool:
        due = self.finding_due(f)
        return bool(due and due < self.now)

    def overdue(self, severity: str, first_seen: datetime | None) -> bool:
        due = self.sla_due(severity, first_seen)
        return bool(due and due < self.now)

    def scanner(self, name: str) -> SimpleNamespace | None:
        return next((s for s in self.scanners if s.name == name), None)

    def scanner_label(self, names: Iterable[str]) -> str:
        out = []
        for n in names:
            s = self.scanner(n)
            title = SCANNER_TITLES.get(n, n)
            out.append(f"{title} {s.version}".strip() if s and s.version else title)
        return "; ".join(out)

    @property
    def open_findings(self) -> list[SimpleNamespace]:
        return [f for f in self.findings if f.status == "open"]

    @property
    def failed_results(self) -> list[SimpleNamespace]:
        return [r for r in self.posture_results if r.status == "fail"]

    @property
    def accepted_results(self) -> list[SimpleNamespace]:
        """Posture results covered by an active risk acceptance (controlsEngine.exceptions)."""
        return [r for r in self.posture_results if r.status == "accepted-risk"]

    @property
    def risk_acceptances(self) -> list[SimpleNamespace]:
        """Configured risk acceptances (controls_engine/exceptions.py) with what they cover in this
        snapshot: accepted posture results and accepted-risk assertion workloads. `active` and
        `review_overdue` are judged at the report's `now`."""
        from ..controls_engine.exceptions import coerce

        today = self.now.date()
        out = []
        for e in coerce(self.engine.get("exceptions") or []):
            results = [r for r in self.accepted_results if e.covers(r.kind, r.namespace, r.name, check=r.check_id)]
            lapsed = [r for r in self.failed_results if not e.active(today)
                      and e.covers(r.kind, r.namespace, r.name, check=r.check_id)]
            assertions = []
            for a in self.engine_results:
                if a.get("id") not in e.assertions:
                    continue
                for w in (a.get("evidence") or {}).get("acceptedRisk") or []:
                    ns, _, rest = str(w.get("workload", "")).partition("/")
                    kind, _, name = rest.partition("/")
                    if e.matches(kind, ns, name):
                        assertions.append(a)
                        break
            sevs = [r.severity for r in results] + [sev(a.get("severity") or "medium") for a in assertions]
            controls = list(dict.fromkeys([*(c for r in results for c in self.check(r.check_id).controls),
                                           *(c for a in assertions for c in a.get("controls") or [])]))
            out.append(SimpleNamespace(
                exception=e, key=e.key, active=e.active(today), review_overdue=e.review_overdue(today),
                results=results, lapsed=lapsed, assertions=assertions,
                checks=sorted({r.check_id for r in results}), assertion_ids=sorted({a.get("id", "") for a in assertions}),
                severity=max(sevs, key=sev_rank) if sevs else "medium", controls=controls))
        return out

    def severity_counts(self, findings: Iterable[SimpleNamespace] | None = None) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.open_findings if findings is None else findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def check(self, check_id: str) -> SimpleNamespace:
        c = self.checks_by_id.get(check_id)
        if c is None:
            s, t = CHECK_DEFAULTS.get(check_id, ("medium", check_id))
            c = SimpleNamespace(id=check_id, title=t, severity=s, category="", description="",
                                remediation="", controls=check_controls(check_id),
                                passed=0, failed=0)
            self.checks_by_id[check_id] = c
        return c

    @property
    def scope_label(self) -> str:
        if self.scope.kind == "cluster" or not self.scope.name:
            return f"Cluster ({self.system.cluster_name or self.system.name})"
        return f"{self.scope.kind.capitalize()} {self.scope.name}"


def _ns(obj: Any, spec: dict[str, Any]) -> SimpleNamespace:
    out = {}
    for k, d in spec.items():
        v = get(obj, k, None)
        if v is None:
            v = d() if callable(d) else d
        out[k] = v
    return SimpleNamespace(**out)


def _list(obj: Any, name: str) -> list:
    v = get(obj, name, None)
    return list(v) if v else []


def _dt_fields(o: SimpleNamespace, *names: str) -> SimpleNamespace:
    for n in names:
        setattr(o, n, as_dt(getattr(o, n)))
    return o


def normalize(snapshot: Any, options: dict[str, Any] | None = None) -> View:
    opts = dict(options or {})
    gen = as_dt(get(snapshot, "generated_at")) or datetime.now(timezone.utc)
    now = as_dt(opts.get("now")) or gen

    system = _ns(get(snapshot, "system", {}), {
        "name": "Nebari cluster", "organization": "", "cluster_name": None, "description": "",
        "hostname": "", "ip_address": "", "host_name": "", "mac_address": "", "poc_name": "", "poc_email": "", "poc_phone": "",
        "classification": "UNCLASSIFIED", "marking": "CUI", "emass_system_id": "",
    })
    if opts.get("systemName"):
        system.name = opts["systemName"]
    scan = _dt_fields(_ns(get(snapshot, "scan", {}), {
        "id": "", "status": "done", "trigger": "", "started_at": None, "finished_at": None,
        "requested_by": "", "score": None, "grade": "?", "vuln_score": None, "posture_score": None,
    }), "started_at", "finished_at")
    scope = _ns(get(snapshot, "scope", {}), {"kind": "cluster", "name": None})
    sla = dict(DEFAULT_SLA_DAYS)
    sla.update({sev(k): int(v) for k, v in (get(snapshot, "sla_days", {}) or {}).items()})

    scanners = [_dt_fields(_ns(s, {"name": "", "enabled": True, "version": "", "db_updated_at": None,
                                   "healthy": True, "last_error": None, "last_run_at": None}),
                           "db_updated_at", "last_run_at") for s in _list(snapshot, "scanners")]
    images = [_dt_fields(_ns(i, {
        "id": None, "ref": "", "registry": "", "repository": "", "tag": "", "digest": "", "score": None,
        "grade": "?", "counts": dict, "fixable": dict, "namespaces": list, "workloads": list, "packs": list,
        "containers": 0, "running_containers": None, "running": False, "os": "", "scanner_status": dict,
        "scanner_versions": dict, "agreement_index": None, "last_scanned_at": None, "mirrored": False,
        "warnings": list, "system_namespace": None, "base_os": None,
    }), "last_scanned_at") for i in _list(snapshot, "images")]
    for i in images:
        i.os = i.os or i.base_os or ""
        i.system_namespace = bool(i.system_namespace) or (
            bool(i.namespaces) and all(n in SYSTEM_NAMESPACES for n in i.namespaces))
        if i.running_containers is None:
            i.running_containers = i.containers if i.running else 0

    findings = []
    for f in _list(snapshot, "findings"):
        o = _dt_fields(_ns(f, {
            "image_id": None, "vuln_id": "", "severity": "unknown", "package": "", "installed_version": "",
            "fixed_version": "", "pkg_type": "", "scanners": list, "agreement": None, "per_scanner": dict,
            "cvss": None, "title": "", "description": "", "url": "", "fixable": None, "first_seen_at": None,
            "controls": list, "status": "open", "fix_published_at": None, "published_at": None,
            "kev": None, "kev_due": None,
            "vex_status": None, "vex_justification": None, "vex_source": None, "vex_detail": None,
        }), "first_seen_at", "fix_published_at", "published_at", "kev_due")
        o.severity = sev(o.severity)
        o.per_scanner = {k: sev(v) for k, v in (o.per_scanner or {}).items()}
        if not o.scanners:
            o.scanners = sorted(o.per_scanner)
        if o.fixable is None:
            o.fixable = bool(o.fixed_version)
        if not o.controls:
            from ..controls import vuln_controls

            o.controls = vuln_controls(bool(o.fixable))
        o.first_seen_at = o.first_seen_at or scan.started_at or gen
        if o.kev is None:  # S2: CISA KEV flag and due date
            from .kev import lookup

            e = lookup(o.vuln_id) if str(o.vuln_id).upper().startswith("CVE-") else None
            o.kev = e is not None
            if e and e.due and not o.kev_due:
                o.kev_due = datetime(e.due.year, e.due.month, e.due.day, tzinfo=timezone.utc)
        else:
            o.kev = bool(o.kev)
        findings.append(o)

    workloads = [_ns(w, {"namespace": "", "kind": "", "name": "", "pack": None, "score": None, "grade": "?",
                         "image_ids": list, "containers": 0, "running": True, "system_namespace": None,
                         "posture": dict, "counts": dict}) for w in _list(snapshot, "workloads")]
    for w in workloads:
        w.system_namespace = bool(w.system_namespace) or w.namespace in SYSTEM_NAMESPACES
        w.key = workload_key(w.namespace, w.kind, w.name)

    checks = [_ns(c, {"id": "", "title": "", "severity": "medium", "category": "", "description": "",
                      "remediation": "", "controls": list, "passed": 0, "failed": 0})
              for c in _list(snapshot, "checks")]
    for c in checks:
        c.severity = sev(c.severity)
        c.controls = list(c.controls) if c.id not in CHECK_CONTROLS else check_controls(c.id)
        c.title = c.title or CHECK_DEFAULTS.get(c.id, ("", c.id))[1]

    results = [_dt_fields(_ns(r, {"check_id": "", "status": "pass", "namespace": "", "kind": "", "name": "",
                                  "container": None, "detail": "", "severity": None, "system_namespace": None,
                                  "first_seen_at": None}), "first_seen_at")
               for r in _list(snapshot, "posture_results")]
    for r in results:
        r.status = str(r.status).lower()
        r.system_namespace = bool(r.system_namespace) or r.namespace in SYSTEM_NAMESPACES
        r.key = workload_key(r.namespace, r.kind, r.name)

    trend = [_dt_fields(_ns(t, {"scan_id": "", "finished_at": None, "score": None, "grade": "?",
                                "critical": 0, "high": 0}), "finished_at") for t in _list(snapshot, "trend")]

    # ------------------------------------------------------------- scope filtering
    include_sys = bool(opts.get("includeSystemNamespaces", True))

    def ns_ok(ns: str) -> bool:
        if not include_sys and ns in SYSTEM_NAMESPACES:
            return False
        if scope.kind == "namespace" and scope.name:
            return ns == scope.name
        if scope.kind == "workload" and scope.name:
            return ns == scope.name.split("/", 1)[0]
        return True

    def wl_ok(key: str, ns: str) -> bool:
        if not ns_ok(ns):
            return False
        return not (scope.kind == "workload" and scope.name) or key == scope.name

    filtered = scope.kind != "cluster" or not include_sys
    if filtered:
        workloads = [w for w in workloads if wl_ok(w.key, w.namespace)]
        results = [r for r in results if wl_ok(r.key, r.namespace)]
        keep_wl = {w.key for w in workloads}
        keep_img = set()
        for w in workloads:
            keep_img.update(w.image_ids)
        for i in images:
            if any(wk in keep_wl for wk in i.workloads):
                keep_img.add(i.id)
            elif not i.workloads and any(ns_ok(n) for n in i.namespaces) and scope.kind == "cluster":
                keep_img.add(i.id)
        images = [i for i in images if i.id in keep_img]
        for i in images:  # narrow usage lists to the scope
            i.workloads = [wk for wk in i.workloads if wk in keep_wl] or i.workloads
            i.namespaces = [n for n in i.namespaces if ns_ok(n)] or i.namespaces
        findings = [f for f in findings if f.image_id in keep_img]

    nss = [_ns(n, {"name": "", "pack": None, "managed": False, "score": None, "grade": "?", "workloads": 0,
                   "images": 0, "system_namespace": None}) for n in _list(snapshot, "namespaces")]
    if not nss:
        by: dict[str, SimpleNamespace] = {}
        for w in workloads:
            n = by.setdefault(w.namespace, SimpleNamespace(name=w.namespace, pack=w.pack, managed=bool(w.pack),
                                                          score=None, grade="?", workloads=0, images=0,
                                                          system_namespace=None))
            n.workloads += 1
        for i in images:
            for nsn in i.namespaces:
                if nsn in by:
                    by[nsn].images += 1
        nss = sorted(by.values(), key=lambda n: n.name)
    nss = [n for n in nss if ns_ok(n.name)]
    for n in nss:
        n.system_namespace = bool(n.system_namespace) or n.name in SYSTEM_NAMESPACES

    view = View(generated_at=gen, now=now, system=system, scan=scan, scope=scope, sla_days=sla,
                scanners=scanners, images=images, findings=findings, workloads=workloads, namespaces=nss,
                checks=checks, posture_results=results, trend=trend, options=opts)
    ce = get(snapshot, "controls_engine", None)
    view.engine = dict(ce) if isinstance(ce, dict) else {}
    view.images_by_id = {i.id: i for i in images}
    view.checks_by_id = {c.id: c for c in checks}
    view.stig_benchmarks = _stig_benchmarks(snapshot, view.images_by_id)
    for r in results:  # make sure every referenced check has a definition
        view.check(r.check_id)
        if not r.severity:
            r.severity = view.check(r.check_id).severity
        r.severity = sev(r.severity)
    return view


CAT_SEVERITY = {"cat1": "high", "cat2": "medium", "cat3": "low"}  # DISA category -> raw severity


def _stig_benchmarks(snapshot: Any, images_by_id: dict[Any, SimpleNamespace]) -> list[SimpleNamespace]:
    out = []
    for b in _list(snapshot, "stig_results"):
        o = _dt_fields(_ns(b, {
            "image_id": None, "benchmark_key": "", "benchmark_id": None, "title": "", "version": "",
            "release_info": "", "source": None, "profile_id": None, "profile_title": None, "content_file": None,
            "status": "evaluated", "counts": dict, "score": None, "cat1_open": 0, "cat2_open": 0, "cat3_open": 0,
            "rootfs_fidelity": None, "evaluated_at": None, "error": None, "os": None, "rules": list}), "evaluated_at")
        if o.image_id not in images_by_id:  # scope filter: only images of the report's scope
            continue
        o.image = images_by_id[o.image_id]
        o.rules = [_dt_fields(_ns(r, {"rule_id": "", "result": "unknown", "severity": "cat2", "title": "",
                                      "stig_id": None, "vuln_id": None, "sv_id": None, "rule_version": None,
                                      "cci": list, "nist": list, "fix_text": None, "group_title": None,
                                      "first_failed_at": None}), "first_failed_at") for r in (o.rules or [])]
        out.append(o)
    return out


def filename(view: View, report: str, ext: str) -> str:
    scope = "" if view.scope.kind == "cluster" or not view.scope.name else f"-{slug(view.scope.name)}"
    stamp = (view.scan.finished_at or view.generated_at).strftime("%Y%m%d")
    return f"{slug(view.system.name)}{scope}-{report}-scan{view.scan.id}-{stamp}.{ext}"
