"""Report catalogue and dispatcher.

    from posture.reports.registry import REPORT_TYPES, generate
    rep = generate("poam", "xlsx", snapshot, {"rollupByCve": True})
    rep.content, rep.filename, rep.content_type      # or: data, name, ctype = rep

`snapshot` is anything satisfying models_contract.md (normally
`posture.reports.models.ReportSnapshot`). Generators are pure and synchronous; call them
from a threadpool / background task in the API.
"""

from __future__ import annotations

import importlib
from typing import Any, Callable, NamedTuple


class GeneratedReport(NamedTuple):
    content: bytes
    filename: str
    content_type: str


class UnsupportedReport(ValueError):
    """Unknown report type or format (map to HTTP 400/422)."""


class ReportDependencyMissing(RuntimeError):
    """An optional runtime dependency (e.g. WeasyPrint system libraries) is unavailable."""


SCOPES = ["cluster", "namespace", "workload"]

REPORT_TYPES: list[dict[str, Any]] = [
    {
        "type": "poam",
        "title": "Plan of Action & Milestones (POA&M)",
        "formats": ["xlsx", "csv"],
        "scopes": SCOPES,
        "options": ["rollupByCve", "systemName", "includeSystemNamespaces", "poamVariant"],
        "description": "eMASS POA&M import layout: one row per consensus finding per image (or per CVE with "
                       "rollupByCve) plus one row per failing posture check, with NIST 800-53 control, "
                       "SLA-based scheduled completion date and mitigation.",
    },
    {
        "type": "stig-checklist",
        "title": "STIG checklist (Kubernetes STIG + Container Platform SRG)",
        "formats": ["ckl", "cklb"],
        "scopes": SCOPES,
        "options": ["systemName", "includeSystemNamespaces", "includeSrg"],
        "description": "STIG Viewer checklist (.ckl for 2.x, .cklb for 3.x). Posture checks mapped to Kubernetes "
                       "STIG V2R6 / Container Platform SRG V2R4 rules; unmapped rules are Not_Reviewed.",
    },
    {
        "type": "sar",
        "title": "Security Assessment Report (SAR)",
        "formats": ["pdf", "html"],
        "scopes": SCOPES,
        "options": ["systemName", "includeSystemNamespaces"],
        "description": "Printable narrative assessment report: scope, methodology, score and trend, inventory, "
                       "findings by severity with scanner agreement, posture results, scanner freshness, "
                       "limitations and appendices.",
    },
    {
        "type": "oscal-ar",
        "title": "OSCAL Assessment Results",
        "formats": ["json"],
        "scopes": SCOPES,
        "options": ["systemName", "includeSystemNamespaces"],
        "description": "NIST OSCAL 1.1.2 assessment-results JSON: one result per scan, observations per finding, "
                       "risks with SLA deadlines, findings per NIST 800-53 control.",
    },
    {
        "type": "inventory",
        "title": "Hardware/Software inventory",
        "formats": ["xlsx", "csv"],
        "scopes": SCOPES,
        "options": ["systemName", "includeSystemNamespaces"],
        "description": "eMASS-style software asset list: every container image with digest, registry, tag, "
                       "namespaces, workloads, pack, running count, base OS and scanner coverage.",
    },
    {
        "type": "vuln-export",
        "title": "Vulnerability export",
        "formats": ["csv", "json", "cyclonedx-vex"],
        "scopes": SCOPES,
        "options": ["includeSystemNamespaces"],
        "description": "Flat findings export, one row per (image, CVE, package) with each scanner's severity; "
                       "CycloneDX 1.6 VEX JSON for tool ingest.",
    },
    {
        "type": "oscal-ssp",
        "title": "OSCAL System Security Plan",
        "formats": ["json"],
        "scopes": ["cluster"],
        "options": ["systemName", "baseline"],
        "description": "NIST OSCAL 1.1.2 system-security-plan importing the NIST SP 800-53 rev5 baseline profile: "
                       "per-control implementation status derived from live control assertions, by-component "
                       "statements and embedded evidence (DESIGN §13).",
    },
    {
        "type": "oscal-component-definition",
        "title": "OSCAL Component Definition",
        "formats": ["json"],
        "scopes": ["cluster"],
        "options": [],
        "description": "NIST OSCAL 1.1.2 component-definition for the Nebari platform components (Keycloak, Envoy "
                       "Gateway, cert-manager, nebari-operator, Loki, Prometheus, Kubernetes, registry, this pack) "
                       "with the 800-53 controls each implements and the assertions that verify them.",
    },
]

_MODULES = {
    "poam": "poam",
    "stig-checklist": "stig",
    "sar": "sar",
    "oscal-ar": "oscal",
    "inventory": "inventory",
    "vuln-export": "vuln_export",
    "oscal-ssp": "oscal_ssp",
    "oscal-component-definition": "oscal_component",
}


def _generator(report_type: str) -> Callable[..., GeneratedReport]:
    mod = _MODULES.get(report_type)
    if mod is None:
        raise UnsupportedReport(f"unknown report type {report_type!r}")
    return importlib.import_module(f"{__package__}.{mod}").generate


def formats_for(report_type: str) -> list[str]:
    for t in REPORT_TYPES:
        if t["type"] == report_type:
            return list(t["formats"])
    raise UnsupportedReport(f"unknown report type {report_type!r}")


def generate(report_type: str, fmt: str, snapshot: Any, options: dict[str, Any] | None = None) -> GeneratedReport:
    fmt = (fmt or "").lower()
    if fmt not in formats_for(report_type):
        raise UnsupportedReport(f"report type {report_type!r} does not support format {fmt!r}")
    content, filename, content_type = _generator(report_type)(fmt, snapshot, dict(options or {}))
    return GeneratedReport(content, filename, content_type)
