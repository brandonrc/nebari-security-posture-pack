"""STIG Viewer checklists: .ckl (STIG Viewer 2.x XML) and .cklb (STIG Viewer 3.x JSON).

Rules come from ``data/stig_mapping.yaml`` (generated from the official DISA XCCDF:
Kubernetes STIG V2R6, all rules; Container Platform SRG V2R4, the subset this tool can
evidence). Each rule's ``evaluation`` block says how to derive its status from the
snapshot; rules we cannot evaluate are emitted as ``Not_Reviewed`` so the checklist is
complete and importable.

``stig_rollup(snapshot, options)`` returns the per-rule status list used by
``GET /compliance/stig``.
"""

from __future__ import annotations

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from ._common import TOOL_NAME, View, filename, image_label, iso, normalize, sev_rank
from .registry import GeneratedReport

MAPPING_PATH = Path(__file__).parent / "data" / "stig_mapping.yaml"
CKL_STATUS = ("NotAFinding", "Open", "Not_Reviewed", "Not_Applicable")
CKLB_STATUS = {"NotAFinding": "not_a_finding", "Open": "open", "Not_Reviewed": "not_reviewed",
               "Not_Applicable": "not_applicable"}
STIG_VIEWER_VERSION = "2.18"
MAX_DETAILS = 30000
NS_UUID = uuid.UUID("7d6a3c8e-3f0b-4b8e-9a52-6c1b5e0b9f10")


@lru_cache(maxsize=1)
def load_mapping() -> dict[str, Any]:
    with open(MAPPING_PATH, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for r in data["rules"]:
        ev = r.setdefault("evaluation", {"method": "none"})
        ev.setdefault("onPass", "NotAFinding")
        ev.setdefault("onFail", "Open")
        for k in ("onPass", "onFail"):
            if ev[k] not in CKL_STATUS:
                raise ValueError(f"{r['vulnId']}: invalid {k} {ev[k]!r}")
    return data


def benchmark(key: str) -> dict[str, Any]:
    return next(b for b in load_mapping()["benchmarks"] if b["key"] == key)


def rules_for_check(check_id: str, include_aggregate: bool = False) -> list[dict[str, Any]]:
    """STIG/SRG rules evidenced by a posture check (catch-all `aggregate` rules excluded by default)."""
    return [r for r in load_mapping()["rules"]
            if r["evaluation"].get("method") == "posture" and check_id in r["evaluation"].get("checks", [])
            and (include_aggregate or not r["evaluation"].get("aggregate"))]


# --------------------------------------------------------------------------- evaluation
def _cap(lines: list[str], header: str) -> str:
    out, size = [header], len(header)
    for i, line in enumerate(lines):
        if size + len(line) > MAX_DETAILS:
            out.append(f"... and {len(lines) - i} more")
            break
        out.append(line)
        size += len(line) + 1
    return "\n".join(out)


def evaluate_rule(rule: dict[str, Any], v: View) -> SimpleNamespace:
    ev = rule["evaluation"]
    method = ev.get("method", "none")
    stamp = f"Evaluated automatically by {TOOL_NAME} from scan {v.scan.id} ({iso(v.scan.finished_at or v.generated_at)})."
    note = ev.get("note", "")
    offenders: list[str] = []
    status, details = "Not_Reviewed", ""

    if method == "posture":
        checks = ev.get("checks", [])
        evaluated = [r for r in v.posture_results if r.check_id in checks and r.status in ("pass", "fail")]
        failed = [r for r in evaluated if r.status == "fail"]
        if not evaluated:
            status, details = "Not_Reviewed", f"No workloads in scope were evaluated for checks: {', '.join(checks)}."
        elif failed:
            status = ev["onFail"]
            offenders = sorted({r.key for r in failed})
            lines = sorted({f"- {r.key}" + (f" [{r.container}]" if r.container else "")
                            + f": {r.check_id}" + (f" ({r.detail})" if r.detail else "")
                            + (" [system namespace]" if r.system_namespace else "") for r in failed})
            details = _cap(lines, f"{len(offenders)} workload(s) / {len(failed)} container check(s) failed "
                                  f"[{', '.join(c for c in checks if any(r.check_id == c for r in failed))}]:")
        else:
            status = ev["onPass"]
            details = (f"All {len({r.key for r in evaluated})} evaluated workload(s) passed: {', '.join(checks)}.")
    elif method == "inventory":
        nss = set(ev.get("namespaces", []))
        hits = [w for w in v.workloads if w.namespace in nss]
        if hits:
            status = ev["onFail"]
            offenders = sorted(w.key for w in hits)
            details = _cap([f"- {k}" for k in offenders],
                           f"{len(hits)} workload(s) found in namespace(s) {', '.join(sorted(nss))}:")
        else:
            status = ev["onPass"]
            details = f"No pod-owning workloads found in namespace(s) {', '.join(sorted(nss))}."
    elif method == "vulnerabilities":
        sevs = set(ev.get("severities", ["critical", "high"]))
        cutoff = v.now - timedelta(days=int(ev["olderThanDays"])) if ev.get("olderThanDays") else None
        hits = [f for f in v.open_findings if f.severity in sevs and (f.fixable or not ev.get("fixableOnly"))
                and (cutoff is None or f.first_seen_at <= cutoff)]
        if hits:
            status = ev["onFail"]
            by_img: dict[Any, list] = {}
            for f in hits:
                by_img.setdefault(f.image_id, []).append(f)
            offenders = [image_label(v.images_by_id[i]) if i in v.images_by_id else str(i) for i in by_img]
            lines = []
            for img_id, fs in by_img.items():
                label = image_label(v.images_by_id[img_id]) if img_id in v.images_by_id else str(img_id)
                fs.sort(key=lambda f: (-sev_rank(f.severity), f.vuln_id))
                lines.append(f"- {label}: " + ", ".join(
                    f"{f.vuln_id} {f.package} ({f.severity}{', fix ' + f.fixed_version if f.fixed_version else ''})"
                    for f in fs[:25]) + (f" ... +{len(fs) - 25}" if len(fs) > 25 else ""))
            age = f" first seen more than {ev['olderThanDays']} days ago" if cutoff else ""
            details = _cap(lines, f"{len(hits)} open {'fixable ' if ev.get('fixableOnly') else ''}"
                                  f"{'/'.join(sorted(sevs, key=sev_rank, reverse=True))} finding(s){age} "
                                  f"in {len(by_img)} image(s):")
        else:
            status = ev["onPass"]
            details = "No matching open vulnerability findings in scope."
    elif method == "scanner-coverage":
        healthy = [s.name for s in v.scanners if s.enabled and s.healthy]
        fresh = v.scan.finished_at and v.scan.finished_at >= v.now - timedelta(days=int(ev.get("maxAgeDays", 7)))
        if healthy and fresh and v.scan.status in ("done", "completed", "ok"):
            status = ev["onPass"]
            details = (f"Continuous scanning in place: scan {v.scan.id} finished {iso(v.scan.finished_at)} with "
                       f"healthy scanner(s): {v.scanner_label(healthy)}; {len(v.images)} image(s) in scope.")
        else:
            status = ev["onFail"]
            details = (f"Scanning is not current: last scan status {v.scan.status!r} finished "
                       f"{iso(v.scan.finished_at) or 'never'}; healthy scanners: {', '.join(healthy) or 'none'}.")
    else:
        status = "Not_Reviewed"
        note = note or "Control-plane / host-level requirement: not evaluated by this tool; requires manual review."

    comments = " ".join(filter(None, [stamp, note]))
    return SimpleNamespace(status=status, details=details, comments=comments, offenders=offenders, method=method)


def _selected_rules(v: View) -> list[dict[str, Any]]:
    include_srg = v.options.get("includeSrg", True)
    return [r for r in load_mapping()["rules"]
            if include_srg or r["benchmark"] == "kubernetes"]


def stig_rollup(snapshot: Any, options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Per-rule status for the API (`GET /compliance/stig`)."""
    v = normalize(snapshot, options)
    out = []
    for r in _selected_rules(v):
        e = evaluate_rule(r, v)
        out.append({"vulnId": r["vulnId"], "ruleId": r["ruleId"], "ruleVersion": r["ruleVersion"],
                    "benchmark": r["benchmark"], "title": r["ruleTitle"], "cat": r["cat"],
                    "severity": r["severity"], "status": e.status, "offenders": e.offenders,
                    "checks": r["evaluation"].get("checks", []), "method": e.method})
    return out


# --------------------------------------------------------------------------- shared structure
def _stig_uuid(v: View, bkey: str) -> str:
    return str(uuid.uuid5(NS_UUID, f"{v.system.name}|{v.scope_label}|{v.scan.id}|{bkey}"))


def _groups(v: View) -> list[tuple[dict, list[tuple[dict, SimpleNamespace]]]]:
    rules = _selected_rules(v)
    out = []
    for b in load_mapping()["benchmarks"]:
        rs = [(r, evaluate_rule(r, v)) for r in rules if r["benchmark"] == b["key"]]
        if rs:
            out.append((b, rs))
    return out


def _host(v: View) -> str:
    return v.system.hostname or v.system.cluster_name or v.system.name


def _target_comment(v: View) -> str:
    return (f"{v.system.name} - {v.scope_label}. Generated by {TOOL_NAME} from scan {v.scan.id} on "
            f"{iso(v.generated_at)}. Machine-generated; review Not_Reviewed items manually.")


def _stig_ref(b: dict) -> str:
    return f"{b['title']} :: Version {b['version']}, {b['releaseInfo']}"


# --------------------------------------------------------------------------- .ckl
def _sub(parent: ET.Element, tag: str, text: Any = None) -> ET.Element:
    el = ET.SubElement(parent, tag)
    if text is not None:
        el.text = str(text)
    return el


def _ckl(v: View) -> bytes:
    groups = _groups(v)
    root = ET.Element("CHECKLIST")
    asset = _sub(root, "ASSET")
    k8s = benchmark("kubernetes")
    for tag, val in [("ROLE", "None"), ("ASSET_TYPE", "Computing"), ("MARKING", v.system.marking),
                     ("HOST_NAME", _host(v)), ("HOST_IP", v.system.ip_address), ("HOST_MAC", ""),
                     ("HOST_FQDN", v.system.hostname), ("TARGET_COMMENT", _target_comment(v)),
                     ("TECH_AREA", ""), ("TARGET_KEY", k8s.get("referenceIdentifier") or ""),
                     ("WEB_OR_DATABASE", "false"), ("WEB_DB_SITE", ""), ("WEB_DB_INSTANCE", "")]:
        _sub(asset, tag, val)
    stigs = _sub(root, "STIGS")
    for b, rules in groups:
        istig = _sub(stigs, "iSTIG")
        info = _sub(istig, "STIG_INFO")
        su = _stig_uuid(v, b["key"])
        for name, val in [("version", b["version"]), ("classification", "UNCLASSIFIED"), ("customname", ""),
                          ("stigid", b["stigId"]), ("description", b.get("description", "")),
                          ("filename", b["filename"]), ("releaseinfo", b["releaseInfo"]), ("title", b["title"]),
                          ("uuid", su), ("notice", b.get("notice", "terms-of-use")),
                          ("source", b.get("source", "STIG.DOD.MIL"))]:
            si = _sub(info, "SI_DATA")
            _sub(si, "SID_NAME", name)
            if val:
                _sub(si, "SID_DATA", val)
        for r, e in rules:
            vuln = _sub(istig, "VULN")
            legacy = (r.get("legacyIds") or []) + ["", ""]
            attrs = [
                ("Vuln_Num", r["vulnId"]), ("Severity", r["severity"]), ("Group_Title", r["groupTitle"]),
                ("Rule_ID", r["ruleId"]), ("Rule_Ver", r["ruleVersion"]), ("Rule_Title", r["ruleTitle"]),
                ("Vuln_Discuss", r.get("discussion", "")), ("IA_Controls", ""),
                ("Check_Content", r.get("checkContent", "")), ("Fix_Text", r.get("fixText", "")),
                ("False_Positives", ""), ("False_Negatives", ""), ("Documentable", "false"),
                ("Mitigations", ""), ("Potential_Impact", ""), ("Third_Party_Tools", ""),
                ("Mitigation_Control", ""), ("Responsibility", ""), ("Security_Override_Guidance", ""),
                ("Check_Content_Ref", r.get("checkContentRef", "M")), ("Weight", r.get("weight", "10.0")),
                ("Class", "Unclass"), ("STIGRef", _stig_ref(b)),
                ("TargetKey", b.get("referenceIdentifier") or ""), ("STIG_UUID", su),
                ("LEGACY_ID", legacy[0]), ("LEGACY_ID", legacy[1]),
                *[("CCI_REF", c) for c in r.get("ccis", [])],
            ]
            for a, val in attrs:
                sd = _sub(vuln, "STIG_DATA")
                _sub(sd, "VULN_ATTRIBUTE", a)
                _sub(sd, "ATTRIBUTE_DATA", val)
            _sub(vuln, "STATUS", e.status)
            _sub(vuln, "FINDING_DETAILS", e.details)
            _sub(vuln, "COMMENTS", e.comments)
            _sub(vuln, "SEVERITY_OVERRIDE", "")
            _sub(vuln, "SEVERITY_JUSTIFICATION", "")
    ET.indent(root, space="\t")
    body = ET.tostring(root, encoding="unicode", short_empty_elements=False)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: {STIG_VIEWER_VERSION}-->\n'
            + body + "\n").encode("utf-8")


# --------------------------------------------------------------------------- .cklb
def _cklb(v: View) -> bytes:
    now = iso(v.generated_at)
    stigs = []
    for b, rules in _groups(v):
        su = _stig_uuid(v, b["key"])
        out_rules = []
        for r, e in rules:
            rule_id = r["ruleId"]
            out_rules.append({
                "uuid": str(uuid.uuid5(NS_UUID, f"{su}|{r['vulnId']}")),
                "stig_uuid": su,
                "target_key": b.get("referenceIdentifier") or None,
                "stig_ref": None,
                "group_id": r["vulnId"],
                "group_id_src": r["vulnId"],
                "rule_id": rule_id[:-5] if rule_id.endswith("_rule") else rule_id,
                "rule_id_src": rule_id,
                "weight": r.get("weight", "10.0"),
                "classification": "Unclassified",
                "severity": r["severity"],
                "rule_version": r["ruleVersion"],
                "group_title": r["groupTitle"],
                "rule_title": r["ruleTitle"],
                "fix_text": r.get("fixText", ""),
                "false_positives": "",
                "false_negatives": "",
                "discussion": r.get("discussion", ""),
                "check_content": r.get("checkContent", ""),
                "documentable": "false",
                "mitigations": "",
                "potential_impacts": "",
                "third_party_tools": "",
                "mitigation_control": "",
                "responsibility": "",
                "security_override_guidance": "",
                "ia_controls": "",
                "check_content_ref": {"href": b["filename"], "name": r.get("checkContentRef", "M")},
                "legacy_ids": list(r.get("legacyIds") or []),
                "ccis": list(r.get("ccis") or []),
                "group_tree": [{"id": r["vulnId"], "title": r["groupTitle"],
                                "description": "<GroupDescription></GroupDescription>"}],
                "reference_identifier": b.get("referenceIdentifier") or "",
                "srg_id": r["groupTitle"].split("-CTR-")[0] if r["groupTitle"].startswith("SRG-") else "",
                "createdAt": now,
                "updatedAt": now,
                "STIGUuid": su,
                "status": CKLB_STATUS[e.status],
                "overrides": {},
                "comments": e.comments,
                "finding_details": e.details,
            })
        stigs.append({
            "stig_name": b["title"],
            "display_name": b["title"].replace(" Security Technical Implementation Guide", "")
                                      .replace(" Security Requirements Guide", " SRG"),
            "stig_id": b["stigId"],
            "release_info": b["releaseInfo"],
            "version": str(b["version"]),
            "uuid": su,
            "reference_identifier": b.get("referenceIdentifier") or "",
            "size": len(out_rules),
            "rules": out_rules,
        })
    doc = {
        "title": f"{v.system.name} - {v.scope_label} - scan {v.scan.id}",
        "id": str(uuid.uuid5(NS_UUID, f"{v.system.name}|{v.scope_label}|{v.scan.id}|cklb")),
        "active": False,
        "mode": 2,
        "has_path": True,
        "target_data": {
            "target_type": "Computing",
            "host_name": _host(v),
            "ip_address": v.system.ip_address,
            "mac_address": "",
            "fqdn": v.system.hostname,
            "comments": _target_comment(v),
            "role": "None",
            "is_web_database": False,
            "technology_area": "",
            "web_db_site": "",
            "web_db_instance": "",
            "classification": None,
        },
        "stigs": stigs,
        "cklb_version": "1.0",
    }
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    if fmt == "ckl":
        return GeneratedReport(_ckl(v), filename(v, "stig-checklist", "ckl"), "application/xml")
    return GeneratedReport(_cklb(v), filename(v, "stig-checklist", "cklb"), "application/json")
