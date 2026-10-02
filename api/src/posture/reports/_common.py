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
from types import SimpleNamespace
from typing import Any, Iterable

SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
SEV_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}  # critical=6 .. unknown=1
DEFAULT_SLA_DAYS = {"critical": 15, "high": 30, "medium": 90, "low": 180, "negligible": 365, "unknown": 180}
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
SCANNERS = ("trivy", "grype", "clair")
SCANNER_TITLES = {"trivy": "Trivy", "grype": "Grype", "clair": "Clair"}
TOOL_NAME = "Nebari Security Posture Pack"

# NIST 800-53 tagging per DESIGN.md §11 (fallback when the snapshot carries no `controls`).
CHECK_CONTROLS: dict[str, list[str]] = {
    "privileged": ["AC-6", "CM-7"],
    "run-as-root": ["AC-6", "CM-7"],
    "privilege-escalation": ["AC-6", "CM-7"],
    "added-capabilities": ["AC-6", "CM-7"],
    "capabilities-not-dropped": ["AC-6", "CM-7"],
    "host-namespaces": ["SC-7", "CM-7"],
    "host-path": ["SC-7", "CM-7"],
    "no-resource-limits": ["SC-6"],
    "no-resource-requests": ["SC-6"],
    "mutable-tag": ["CM-2", "CM-14"],
    "no-liveness-probe": ["SI-13"],
    "no-readiness-probe": ["SI-13"],
    "automount-sa-token": ["AC-6(10)", "IA-5"],
    "seccomp-unconfined": ["CM-6", "SI-16"],
    "no-netpol": ["SC-7", "AC-4"],
    "writable-rootfs": ["CM-6", "CM-7"],
}

CONTROL_TITLES = {
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AC-6(10)": "Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions",
    "CM-2": "Baseline Configuration",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-14": "Signed Components",
    "IA-5": "Authenticator Management",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-6": "Resource Availability",
    "SC-7": "Boundary Protection",
    "SI-2": "Flaw Remediation",
    "SI-2(2)": "Flaw Remediation | Automated Flaw Remediation Status",
    "SI-13": "Predictable Failure Prevention",
    "SI-16": "Memory Protection",
}

def _load_controls_yaml() -> None:
    """Prefer the shared data/controls.yaml (owned by the API) over the fallbacks above."""
    from pathlib import Path

    path = Path(__file__).parent / "data" / "controls.yaml"
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # missing file / yaml: keep built-in fallbacks
        return
    CONTROL_TITLES.update({str(k): str(v) for k, v in (data.get("titles") or {}).items()})
    CHECK_CONTROLS.update({str(k): list(v) for k, v in (data.get("checks") or {}).items() if v})


_load_controls_yaml()

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

    # ---- derived helpers
    def sla_due(self, severity: str, first_seen: datetime | None) -> datetime | None:
        base = first_seen or self.scan.started_at or self.generated_at
        return base + timedelta(days=self.sla_days.get(severity, DEFAULT_SLA_DAYS["unknown"])) if base else None

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
                                remediation="", controls=CHECK_CONTROLS.get(check_id, ["CM-6"]),
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
        "hostname": "", "ip_address": "", "poc_name": "", "poc_email": "", "poc_phone": "",
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
            "controls": list, "status": "open",
        }), "first_seen_at")
        o.severity = sev(o.severity)
        o.per_scanner = {k: sev(v) for k, v in (o.per_scanner or {}).items()}
        if not o.scanners:
            o.scanners = sorted(o.per_scanner)
        if o.fixable is None:
            o.fixable = bool(o.fixed_version)
        if not o.controls:
            o.controls = ["RA-5", "SI-2"] + (["SI-2(2)"] if o.fixable else [])
        o.first_seen_at = o.first_seen_at or scan.started_at or gen
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
        c.controls = list(c.controls) or CHECK_CONTROLS.get(c.id, ["CM-6"])
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
    view.images_by_id = {i.id: i for i in images}
    view.checks_by_id = {c.id: c for c in checks}
    for r in results:  # make sure every referenced check has a definition
        view.check(r.check_id)
        if not r.severity:
            r.severity = view.check(r.check_id).severity
        r.severity = sev(r.severity)
    return view


def filename(view: View, report: str, ext: str) -> str:
    scope = "" if view.scope.kind == "cluster" or not view.scope.name else f"-{slug(view.scope.name)}"
    stamp = (view.scan.finished_at or view.generated_at).strftime("%Y%m%d")
    return f"{slug(view.system.name)}{scope}-{report}-scan{view.scan.id}-{stamp}.{ext}"
