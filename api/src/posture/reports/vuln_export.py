"""Flat vulnerability export: csv / json (one row per image x CVE x package, every
scanner's severity) and CycloneDX 1.6 VEX JSON (one vulnerability per CVE, affects = images)."""

from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

from ._common import SCANNERS, TOOL_NAME, View, filename, image_label, iso, normalize, sev_rank, ymd
from .registry import GeneratedReport

CSV_COLUMNS = [
    "Image Reference", "Image Digest", "Namespaces", "Workloads", "Vulnerability ID", "Package",
    "Installed Version", "Fixed Version", "Package Type", "Consensus Severity", "Trivy Severity",
    "Grype Severity", "Clair Severity", "Scanners", "Agreement", "CVSS", "Fixable", "Title", "URL",
    "NIST 800-53 Controls", "First Seen", "SLA Due", "Overdue", "Status",
]
CDX_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
                "negligible": "info", "unknown": "unknown"}


def _records(v: View) -> list[dict[str, Any]]:
    out = []
    for f in sorted(v.findings, key=lambda f: (-sev_rank(f.severity), f.vuln_id, f.package, str(f.image_id))):
        img = v.images_by_id.get(f.image_id)
        due = v.sla_due(f.severity, f.first_seen_at)
        out.append({
            "imageId": f.image_id,
            "imageRef": img.ref if img else "",
            "imageDigest": img.digest if img else "",
            "namespaces": list(img.namespaces) if img else [],
            "workloads": list(img.workloads) if img else [],
            "vulnId": f.vuln_id,
            "package": f.package,
            "installedVersion": f.installed_version,
            "fixedVersion": f.fixed_version or "",
            "pkgType": f.pkg_type,
            "severity": f.severity,
            "perScanner": {s: f.per_scanner.get(s, "") for s in SCANNERS},
            "scanners": list(f.scanners),
            "agreement": f.agreement,
            "cvss": f.cvss,
            "fixable": bool(f.fixable),
            "title": f.title,
            "url": f.url,
            "controls": list(f.controls),
            "firstSeenAt": iso(f.first_seen_at),
            "slaDueAt": iso(due),
            "overdue": f.status == "open" and v.overdue(f.severity, f.first_seen_at),
            "status": f.status,
        })
    return out


def _csv(v: View) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for r in _records(v):
        w.writerow([
            r["imageRef"], r["imageDigest"], "; ".join(r["namespaces"]), "; ".join(r["workloads"]), r["vulnId"],
            r["package"], r["installedVersion"], r["fixedVersion"], r["pkgType"], r["severity"],
            r["perScanner"]["trivy"], r["perScanner"]["grype"], r["perScanner"]["clair"], "; ".join(r["scanners"]),
            "" if r["agreement"] is None else round(r["agreement"], 3), "" if r["cvss"] is None else r["cvss"],
            "Yes" if r["fixable"] else "No", r["title"], r["url"], "; ".join(r["controls"]),
            r["firstSeenAt"][:10], r["slaDueAt"][:10], "Yes" if r["overdue"] else "No", r["status"],
        ])
    return buf.getvalue().encode("utf-8-sig")


def _json(v: View) -> bytes:
    doc = {
        "generator": TOOL_NAME,
        "generatedAt": iso(v.generated_at),
        "system": {"name": v.system.name, "organization": v.system.organization},
        "scan": {"id": v.scan.id, "finishedAt": iso(v.scan.finished_at), "score": v.scan.score,
                 "grade": v.scan.grade},
        "scope": {"kind": v.scope.kind, "name": v.scope.name},
        "slaDays": v.sla_days,
        "scanners": [{"name": s.name, "version": s.version, "dbUpdatedAt": iso(s.db_updated_at),
                      "healthy": s.healthy} for s in v.scanners],
        "findings": _records(v),
    }
    return json.dumps(doc, indent=2, default=str).encode("utf-8")


def _purl(img: Any) -> str:
    name = (img.repository or img.ref.split("@")[0].rsplit(":", 1)[0]).rsplit("/", 1)[-1]
    q = []
    repo_url = "/".join(p for p in (img.registry, img.repository) if p)
    if repo_url:
        q.append(f"repository_url={repo_url}")
    if img.tag:
        q.append(f"tag={img.tag}")
    ver = f"@{img.digest.replace(':', '%3A')}" if img.digest else ""
    return f"pkg:oci/{name}{ver}" + (f"?{'&'.join(q)}" if q else "")


def _cyclonedx(v: View) -> bytes:
    ns = uuid.UUID("0f9d4c55-3a8e-4f43-9a3f-1a2b3c4d5e6f")
    comps = []
    for i in v.images:
        comps.append({"type": "container", "bom-ref": image_label(i), "name": i.repository or i.ref,
                      "version": i.digest or i.tag, "purl": _purl(i),
                      "properties": [{"name": "nebari:namespaces", "value": ", ".join(i.namespaces)},
                                     {"name": "nebari:workloads", "value": ", ".join(i.workloads)}]})
    by_vuln: dict[str, list] = {}
    for f in v.findings:
        by_vuln.setdefault(f.vuln_id, []).append(f)
    vulns = []
    for vid, fs in sorted(by_vuln.items()):
        f0 = max(fs, key=lambda f: sev_rank(f.severity))
        ratings = [{"source": {"name": "consensus"}, "severity": CDX_SEVERITY[f0.severity], "method": "other"}]
        for s in SCANNERS:
            sv = next((f.per_scanner[s] for f in fs if s in f.per_scanner), None)
            if sv:
                ratings.append({"source": {"name": s}, "severity": CDX_SEVERITY.get(sv, "unknown"),
                                "method": "other"})
        if f0.cvss is not None:
            ratings.append({"source": {"name": "cvss"}, "score": f0.cvss, "method": "CVSSv31",
                            "severity": CDX_SEVERITY[f0.severity]})
        fixed = sorted({f"{f.package} {f.fixed_version}" for f in fs if f.fixed_version})
        src_name = "GHSA" if vid.startswith("GHSA") else "NVD" if vid.startswith("CVE") else "OTHER"
        entry = {
            "bom-ref": f"vuln-{vid}",
            "id": vid,
            "source": {"name": src_name, **({"url": f0.url} if f0.url else {})},
            "ratings": ratings,
            "description": f0.title or f0.description or vid,
            "recommendation": ("Upgrade " + "; ".join(fixed)) if fixed else "No fix available; monitor vendor.",
            "analysis": {
                "state": "in_triage",
                "detail": (f"Detected by {', '.join(sorted({s for f in fs for s in f.scanners}))} in "
                           f"{len({f.image_id for f in fs})} image(s); not yet triaged by the ISSO."),
            },
            "affects": sorted(({"ref": image_label(v.images_by_id[i])} for i in {f.image_id for f in fs}
                               if i in v.images_by_id), key=lambda a: a["ref"]),
            "properties": [{"name": "nebari:package", "value": f"{f.package}@{f.installed_version}"}
                           for f in sorted(fs, key=lambda f: f.package)][:50]
                          + [{"name": "nebari:slaDue", "value": ymd(v.sla_due(f0.severity,
                                                                              min(f.first_seen_at for f in fs)))}],
        }
        if f0.url:
            entry["advisories"] = [{"url": f0.url}]
        vulns.append(entry)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(ns, f'{v.system.name}|{v.scope_label}|{v.scan.id}')}",
        "version": 1,
        "metadata": {
            "timestamp": iso(v.generated_at),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME}]
                      + [{"type": "application", "name": s.name, "version": s.version or "unknown"}
                         for s in v.scanners]},
            "component": {"type": "platform", "bom-ref": "system", "name": v.system.name},
        },
        "components": comps,
        "vulnerabilities": vulns,
    }
    return json.dumps(doc, indent=2).encode("utf-8")


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    if fmt == "csv":
        return GeneratedReport(_csv(v), filename(v, "vulnerabilities", "csv"), "text/csv; charset=utf-8")
    if fmt == "json":
        return GeneratedReport(_json(v), filename(v, "vulnerabilities", "json"), "application/json")
    return GeneratedReport(_cyclonedx(v), filename(v, "vex", "cdx.json"), "application/vnd.cyclonedx+json")
