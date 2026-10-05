"""STIG Viewer checklists: .ckl (STIG Viewer 2.x XML) and .cklb (STIG Viewer 3.x JSON).

Rules come from ``data/stig_mapping.yaml`` (generated from the official DISA XCCDF:
Kubernetes STIG V2R6, all rules; Container Platform SRG V2R4, the subset this tool can
evidence). Each rule's ``evaluation`` block says how to derive its status from the
snapshot; rules we cannot evaluate are emitted as ``Not_Reviewed`` so the checklist is
complete and importable.

``stig_rollup(snapshot, options)`` returns the per-rule status list used by
``GET /compliance/stig``.

Product / OS STIGs (DESIGN §14): every (image, benchmark) evaluated by the SCAP stage becomes its
own checklist with OpenSCAP's real results (pass -> NotAFinding, fail -> Open, notapplicable ->
Not_Applicable, notchecked / error / unknown / informational -> Not_Reviewed); the asset is the
image (ref + digest). Format ``zip`` returns ``stig-bundle.zip``: the Kubernetes checklist plus one
.ckl and one .cklb per (image, benchmark); options ``imageId`` + ``benchmarkId`` with ckl / cklb
return that single product checklist.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
import xml.etree.ElementTree as ET
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from ..logs import get_logger
from ._common import (CAT_SEVERITY, NO_CCI_NOTE, TOOL_NAME, View, filename, image_label, iso, normalize, sev_rank,
                      slug)
from .registry import GeneratedReport

log = get_logger(__name__)
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
        # accepted-risk (controlsEngine.exceptions) stays a finding in the checklist (never NotAFinding);
        # its detail carries the acceptance
        evaluated = [r for r in v.posture_results if r.check_id in checks
                     and r.status in ("pass", "fail", "accepted-risk")]
        failed = [r for r in evaluated if r.status != "pass"]
        if not evaluated:
            status, details = "Not_Reviewed", f"No workloads in scope were evaluated for checks: {', '.join(checks)}."
        elif failed:
            exempt = [r for r in failed if r.system_namespace] if ev.get("exemptNamespaces") else []
            counted = [r for r in failed if r not in exempt]
            exempt_lines = sorted({f"- {r.key}" + (f" [{r.container}]" if r.container else "") + f": {r.check_id}"
                                   for r in exempt})
            if counted:
                status = ev["onFail"]
                offenders = sorted({r.key for r in counted})
                lines = sorted({f"- {r.key}" + (f" [{r.container}]" if r.container else "")
                                + f": {r.check_id}" + (f" ({r.detail})" if r.detail else "")
                                + (" [system namespace]" if r.system_namespace else "") for r in counted})
                details = _cap(lines, f"{len(offenders)} workload(s) / {len(counted)} container check(s) failed "
                                      f"[{', '.join(c for c in checks if any(r.check_id == c for r in counted))}]:")
                if exempt_lines:
                    details += "\n" + _cap(exempt_lines, "Verify exemption (PSA-exempt system namespaces, not counted):")
            else:  # M6: only exempt (system) namespaces fail: the reviewer verifies the exemption
                status = "Not_Reviewed"
                offenders = sorted({r.key for r in exempt})
                details = _cap(exempt_lines, "Verify exemption: failures only in namespaces exempted from Pod Security "
                                             "admission (Kubernetes system namespaces):")
        else:
            status = ev["onPass"]
            details = (f"All {len({r.key for r in evaluated})} evaluated workload(s) passed: {', '.join(checks)}.")
            if ev.get("requireRestrictedPsa"):
                ok, why = _psa_restricted_everywhere(v)
                details += " " + why
                if not ok:
                    status = "Not_Reviewed"
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
        candidates = [f for f in v.open_findings if f.severity in sevs and (f.fixable or not ev.get("fixableOnly"))]
        undated: list[Any] = []
        if ev.get("clock") == "fixRelease":  # M6: the clock runs from the update's release
            undated = [f for f in candidates if f.fix_published_at is None]
            hits = [f for f in candidates if f.fix_published_at is not None
                    and (cutoff is None or f.fix_published_at <= cutoff)]
        else:
            hits = [f for f in candidates if cutoff is None or f.first_seen_at <= cutoff]
        if not hits and undated:
            status = "Not_Reviewed"
            details = (f"{len(undated)} open fixable finding(s) have no known fix release date, so the "
                       f"{ev.get('olderThanDays')}-day window cannot be evaluated; review against the vendor "
                       "advisories (first-seen-by-this-tool is not the release date).")
        elif hits:
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
            age = ((f" with a fix released more than {ev['olderThanDays']} days ago" if ev.get("clock") == "fixRelease"
                    else f" first seen more than {ev['olderThanDays']} days ago") if cutoff else "")
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


def _psa_restricted_everywhere(v: View) -> tuple[bool, str]:
    """Pod Security Admission `restricted` enforced on every in-scope non-system namespace, from the
    control evidence run's k8s-pod-security-admission evidence (M6)."""
    res = next((r for r in v.engine_results if r.get("id") == "k8s-pod-security-admission"), None)
    if not res:
        return False, "Pod Security Admission enforcement was not evidenced (no control evidence run): Not_Reviewed."
    ev = res.get("evidence") or {}
    levels = {**{ns: None for ns in ev.get("notEnforced") or {}}, **(ev.get("enforced") or {})}
    scope = {w.namespace for w in v.workloads if not w.system_namespace} or {n for n in levels}
    weak = sorted(ns for ns in scope if levels.get(ns) != "restricted")
    if weak:
        return False, ("Pod Security Admission does not enforce 'restricted' on: " + ", ".join(weak[:20])
                       + (" ..." if len(weak) > 20 else "") + "; an observed absence is not enforcement: Not_Reviewed.")
    return True, f"Pod Security Admission enforces 'restricted' on all {len(scope)} in-scope namespace(s)."


def asset_warnings(v: View) -> list[str]:
    """eMASS asset import / HW-SW reconciliation needs real identifiers (M6)."""
    missing = [n for n, val in (("HOST_NAME", v.system.host_name), ("HOST_IP", v.system.ip_address),
                                ("HOST_FQDN", v.system.hostname)) if not val]
    return [f"{', '.join(missing)} not configured (settings controlsEngine.stigAsset); eMASS asset import needs "
            "real identifiers"] if missing else []


def _selected_rules(v: View) -> list[dict[str, Any]]:
    # M6: the SRG is assessed only on request (assess the product STIG, not its SRG); then all rules
    include_srg = bool(v.options.get("includeSrg", False))
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
    return v.system.host_name or v.system.hostname or v.system.cluster_name or v.system.name


def _target_comment(v: View) -> str:
    warn = " ".join(f"WARNING: {w}." for w in asset_warnings(v))
    return (f"{v.system.name} - {v.scope_label}. Generated by {TOOL_NAME} from {v.run_stamp} on "
            f"{iso(v.generated_at)}. Machine-generated; review Not_Reviewed items manually." + (f" {warn}" if warn else ""))


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
                     ("HOST_NAME", _host(v)), ("HOST_IP", v.system.ip_address), ("HOST_MAC", v.system.mac_address),
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
            "mac_address": v.system.mac_address,
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


# --------------------------------------------------------------------------- product checklists (§14)
PRODUCT_STATUS = {"pass": "NotAFinding", "fail": "Open", "notapplicable": "Not_Applicable"}


def product_status(result: str) -> str:
    return PRODUCT_STATUS.get(result, "Not_Reviewed")


def _p_uuid(v: View, b: Any) -> str:
    return str(uuid.uuid5(NS_UUID, f"{v.system.name}|image|{b.image_id}|{b.benchmark_key}|{v.scan.id}"))


def _p_host(b: Any) -> str:
    return b.image.ref.split("@", 1)[0]


def _p_comment(v: View, b: Any) -> str:
    fid = (" Rootfs extracted without root (degraded fidelity): owner / mode / setuid rules may be inaccurate."
           if b.rootfs_fidelity == "degraded" else "")
    return (f"Container image {image_label(b.image)}. {b.title} ({b.profile_title or b.profile_id}) evaluated by "
            f"OpenSCAP in offline (chroot) mode on {iso(b.evaluated_at) or 'unknown date'} by {TOOL_NAME} ({v.run_stamp})."
            " Rules that need a running system are Not_Reviewed / Not_Applicable." + fid)


def _p_rule(v: View, b: Any, r: Any) -> dict[str, Any]:
    status = product_status(r.result)
    detail = (f"OpenSCAP result: {r.result} (profile {b.profile_id}) for image {image_label(b.image)}, "
              f"evaluated {iso(b.evaluated_at)}.")
    if r.result in ("notchecked", "error", "unknown", "informational"):
        detail += " Not evaluable automatically in a container image; review manually."
    if not r.cci and (r.vuln_id or r.sv_id):
        detail += " " + NO_CCI_NOTE
    return {"vuln": r.vuln_id or r.stig_id or r.rule_id, "rule": r.sv_id or r.rule_id, "ver": r.rule_version or "",
            "group": r.group_title or r.vuln_id or "", "severity": CAT_SEVERITY.get(r.severity, "low"),
            "title": r.title or r.rule_id, "fix": r.fix_text or "", "ccis": list(r.cci or []), "status": status,
            "details": detail, "comments": f"Evaluated automatically by {TOOL_NAME} (OpenSCAP) from scan {v.scan.id}."}


def _product_ckl(v: View, b: Any) -> bytes:
    root = ET.Element("CHECKLIST")
    asset = _sub(root, "ASSET")
    for tag, val in [("ROLE", "None"), ("ASSET_TYPE", "Computing"), ("MARKING", v.system.marking),
                     ("HOST_NAME", _p_host(b)), ("HOST_IP", ""), ("HOST_MAC", ""),
                     ("HOST_FQDN", image_label(b.image)), ("TARGET_COMMENT", _p_comment(v, b)), ("TECH_AREA", ""),
                     ("TARGET_KEY", ""), ("WEB_OR_DATABASE", "false"), ("WEB_DB_SITE", ""), ("WEB_DB_INSTANCE", "")]:
        _sub(asset, tag, val)
    istig = _sub(_sub(root, "STIGS"), "iSTIG")
    info = _sub(istig, "STIG_INFO")
    su = _p_uuid(v, b)
    for name, val in [("version", b.version), ("classification", "UNCLASSIFIED"), ("customname", ""),
                      ("stigid", b.benchmark_id or b.benchmark_key), ("description", b.profile_title or ""),
                      ("filename", b.content_file or ""), ("releaseinfo", b.release_info), ("title", b.title),
                      ("uuid", su), ("notice", "terms-of-use"), ("source", b.source or "")]:
        si = _sub(info, "SI_DATA")
        _sub(si, "SID_NAME", name)
        if val:
            _sub(si, "SID_DATA", val)
    ref = f"{b.title} :: Version {b.version}" + (f", {b.release_info}" if b.release_info else "")
    for r in b.rules:
        x = _p_rule(v, b, r)
        vuln = _sub(istig, "VULN")
        attrs = [("Vuln_Num", x["vuln"]), ("Severity", x["severity"]), ("Group_Title", x["group"]),
                 ("Rule_ID", x["rule"]), ("Rule_Ver", x["ver"]), ("Rule_Title", x["title"]), ("Vuln_Discuss", ""),
                 ("IA_Controls", ""), ("Check_Content", ""), ("Fix_Text", x["fix"]), ("False_Positives", ""),
                 ("False_Negatives", ""), ("Documentable", "false"), ("Mitigations", ""), ("Potential_Impact", ""),
                 ("Third_Party_Tools", ""), ("Mitigation_Control", ""), ("Responsibility", ""),
                 ("Security_Override_Guidance", ""), ("Check_Content_Ref", "M"), ("Weight", "10.0"),
                 ("Class", "Unclass"), ("STIGRef", ref), ("TargetKey", ""), ("STIG_UUID", su),
                 *[("CCI_REF", c) for c in x["ccis"]]]
        for a, val in attrs:
            sd = _sub(vuln, "STIG_DATA")
            _sub(sd, "VULN_ATTRIBUTE", a)
            _sub(sd, "ATTRIBUTE_DATA", val)
        _sub(vuln, "STATUS", x["status"])
        _sub(vuln, "FINDING_DETAILS", x["details"])
        _sub(vuln, "COMMENTS", x["comments"])
        _sub(vuln, "SEVERITY_OVERRIDE", "")
        _sub(vuln, "SEVERITY_JUSTIFICATION", "")
    ET.indent(root, space="\t")
    body = ET.tostring(root, encoding="unicode", short_empty_elements=False)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: {STIG_VIEWER_VERSION}-->\n'
            + body + "\n").encode("utf-8")


def _product_cklb(v: View, b: Any) -> bytes:
    now = iso(v.generated_at)
    su = _p_uuid(v, b)
    rules = []
    for r in b.rules:
        x = _p_rule(v, b, r)
        rules.append({
            "uuid": str(uuid.uuid5(NS_UUID, f"{su}|{r.rule_id}")), "stig_uuid": su, "target_key": None,
            "stig_ref": None, "group_id": x["vuln"], "group_id_src": x["vuln"],
            "rule_id": x["rule"][:-5] if x["rule"].endswith("_rule") else x["rule"], "rule_id_src": x["rule"],
            "weight": "10.0", "classification": "Unclassified", "severity": x["severity"], "rule_version": x["ver"],
            "group_title": x["group"], "rule_title": x["title"], "fix_text": x["fix"], "false_positives": "",
            "false_negatives": "", "discussion": "", "check_content": "", "documentable": "false",
            "mitigations": "", "potential_impacts": "", "third_party_tools": "", "mitigation_control": "",
            "responsibility": "", "security_override_guidance": "", "ia_controls": "",
            "check_content_ref": {"href": b.content_file or "", "name": "M"}, "legacy_ids": [],
            "ccis": x["ccis"], "group_tree": [{"id": x["vuln"], "title": x["group"],
                                               "description": "<GroupDescription></GroupDescription>"}],
            "reference_identifier": "", "srg_id": x["group"] if x["group"].startswith("SRG-") else "",
            "createdAt": now, "updatedAt": now, "STIGUuid": su, "status": CKLB_STATUS[x["status"]],
            "overrides": {}, "comments": x["comments"], "finding_details": x["details"]})
    doc = {
        "title": f"{_p_host(b)} - {b.title} - scan {v.scan.id}",
        "id": str(uuid.uuid5(NS_UUID, f"{su}|cklb")), "active": False, "mode": 2, "has_path": True,
        "target_data": {"target_type": "Computing", "host_name": _p_host(b), "ip_address": "", "mac_address": "",
                        "fqdn": image_label(b.image), "comments": _p_comment(v, b), "role": "None",
                        "is_web_database": False, "technology_area": "", "web_db_site": "", "web_db_instance": "",
                        "classification": None},
        "stigs": [{"stig_name": b.title, "display_name": b.title, "stig_id": b.benchmark_id or b.benchmark_key,
                   "release_info": b.release_info, "version": str(b.version), "uuid": su, "reference_identifier": "",
                   "size": len(rules), "rules": rules}],
        "cklb_version": "1.0",
    }
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def product_filename(v: View, b: Any, ext: str) -> str:
    stamp = (v.scan.finished_at or v.generated_at).strftime("%Y%m%d")
    return f"{slug(_p_host(b))[:80]}-{b.benchmark_key}-scan{v.scan.id}-{stamp}.{ext}"


def _bundle(v: View) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"kubernetes/{filename(v, 'stig-checklist', 'ckl')}", _ckl(v))
        zf.writestr(f"kubernetes/{filename(v, 'stig-checklist', 'cklb')}", _cklb(v))
        index = []
        for b in v.stig_evaluated:
            for ext, fn in (("ckl", _product_ckl), ("cklb", _product_cklb)):
                zf.writestr(f"products/{product_filename(v, b, ext)}", fn(v, b))
            index.append({"image": image_label(b.image), "benchmark": b.benchmark_key, "title": b.title,
                          "profile": b.profile_id, "score": b.score, **{k: int((b.counts or {}).get(k, 0))
                                                                        for k in ("pass", "fail", "notapplicable",
                                                                                  "notchecked")},
                          "file": product_filename(v, b, "ckl")})
        skipped = [{"image": image_label(b.image), "status": b.status, "reason": b.error}
                   for b in v.stig_benchmarks if not (b.status == "evaluated" and b.benchmark_key)]
        zf.writestr("products/index.json", json.dumps({"scan": v.scan.id, "generatedAt": iso(v.generated_at),
                                                       "checklists": index, "notEvaluated": skipped}, indent=2))
    return buf.getvalue()


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    for w in asset_warnings(v):
        log.warning("stig.asset_identifiers_missing", warning=w)
    if fmt == "zip":
        return GeneratedReport(_bundle(v), filename(v, "stig-bundle", "zip"), "application/zip")
    if options.get("imageId") is not None or options.get("benchmarkId"):
        want_img, want_b = str(options.get("imageId")), options.get("benchmarkId")
        b = next((b for b in v.stig_evaluated if str(b.image_id) == want_img
                  and (not want_b or b.benchmark_key == want_b)), None)
        if b is None:
            from .registry import UnsupportedReport

            raise UnsupportedReport(f"no evaluated product STIG for image {want_img} / benchmark {want_b or 'any'}")
        if fmt == "ckl":
            return GeneratedReport(_product_ckl(v, b), product_filename(v, b, "ckl"), "application/xml")
        return GeneratedReport(_product_cklb(v, b), product_filename(v, b, "cklb"), "application/json")
    if fmt == "ckl":
        return GeneratedReport(_ckl(v), filename(v, "stig-checklist", "ckl"), "application/xml")
    return GeneratedReport(_cklb(v), filename(v, "stig-checklist", "cklb"), "application/json")
