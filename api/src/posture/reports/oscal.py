"""NIST OSCAL 1.1.2 Assessment Results (JSON).

Shape:
  assessment-results
    metadata            title/version/parties (organization) / props (system, scope, scan)
    import-ap           href to a back-matter resource describing the implicit
                        continuous-monitoring assessment plan (no separate AP document)
    results[0]          one result per scan
      local-definitions components = scanner tools + this pack; inventory-items = images
                        and workloads (subjects of observations)
      reviewed-controls the NIST 800-53 controls touched (ra-5, si-2, cm-6, ...)
      observations      one per (image, vuln, package) and one per failing posture check
      risks             one per CVE and per failing posture check (deadline = SLA due date)
      findings          one per control, target statement satisfied / not-satisfied
    back-matter         assessment-plan stub + scanner references

UUIDs are deterministic (v5) so regenerating the same scan yields identical documents.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from ._common import (control_title, SCANNER_TITLES, TOOL_NAME, View, filename, image_label, iso, normalize,
                      sev_rank)
from .registry import GeneratedReport

OSCAL_VERSION = "1.1.2"
NS = "https://nebari.dev/ns/oscal"
UUID_NS = uuid.UUID("5b0f3a43-2a1b-4bb5-9a0e-8d7c6e5f4a31")


def control_id(c: str) -> str:
    """'SI-2(2)' -> 'si-2.2' (OSCAL catalog id form)."""
    m = re.match(r"^\s*([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?\s*$", c)
    if not m:
        return c.strip().lower()
    base = f"{m.group(1).lower()}-{int(m.group(2))}"
    return f"{base}.{int(m.group(3))}" if m.group(3) else base


def _prop(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "ns": NS, "value": str(value)}


def _clean(text: str) -> str:
    return (text or "").strip() or "-"


def build(v: View) -> dict[str, Any]:
    seed = f"{v.system.name}|{v.scope_label}|{v.scan.id}"

    def uid(*parts: Any) -> str:
        return str(uuid.uuid5(UUID_NS, seed + "|" + "|".join(str(p) for p in parts)))

    collected = iso(v.scan.finished_at or v.generated_at)

    # ---- components (tools)
    tool_uuid = uid("component", "pack")
    components = [{
        "uuid": tool_uuid, "type": "software", "title": TOOL_NAME,
        "description": "Nebari software pack that inventories cluster workloads, scans images with Trivy, "
                       "Grype and Clair, correlates results and evaluates Kubernetes posture checks.",
        "status": {"state": "operational"},
    }]
    scanner_uuid: dict[str, str] = {}
    for s in v.scanners:
        scanner_uuid[s.name] = uid("component", s.name)
        props = [_prop("scanner", s.name)]
        if s.version:
            props.append({"name": "version", "value": str(s.version)})
        if s.db_updated_at:
            props.append(_prop("db-updated-at", iso(s.db_updated_at)))
        components.append({
            "uuid": scanner_uuid[s.name], "type": "software", "title": SCANNER_TITLES.get(s.name, s.name),
            "description": f"{SCANNER_TITLES.get(s.name, s.name)} container vulnerability scanner"
                           + (f" {s.version}" if s.version else "") + ".",
            "props": props,
            "status": {"state": "operational" if (s.enabled and s.healthy) else "disposition"},
        })

    # ---- inventory items (subjects)
    img_uuid = {i.id: uid("image", i.id) for i in v.images}
    wl_uuid = {w.key: uid("workload", w.key) for w in v.workloads}
    inventory = []
    for i in v.images:
        props = [{"name": "asset-type", "value": "software"}, _prop("image-ref", i.ref)]
        if i.digest:
            props.append(_prop("image-digest", i.digest))
        if i.os:
            props.append(_prop("base-os", i.os))
        if i.grade:
            props.append(_prop("grade", i.grade))
        inventory.append({"uuid": img_uuid[i.id], "description": f"Container image {image_label(i)}",
                          "props": props})
    for r in v.failed_results:  # workloads referenced by posture results but absent from v.workloads
        if r.key not in wl_uuid:
            wl_uuid[r.key] = uid("workload", r.key)
    for key, u in wl_uuid.items():
        ns, kind, name = (key.split("/", 2) + ["", ""])[:3]
        inventory.append({"uuid": u, "description": f"Kubernetes {kind} {name} in namespace {ns}",
                          "props": [{"name": "asset-type", "value": "appliance"}, _prop("workload", key)]})

    observations, risks = [], []
    control_obs: dict[str, list[str]] = {}
    control_risks: dict[str, list[str]] = {}
    control_fail: set[str] = set()

    # ---- vulnerability observations / risks
    by_vuln: dict[str, list] = {}
    for f in v.open_findings:
        by_vuln.setdefault(f.vuln_id, []).append(f)
    for vid, fs in sorted(by_vuln.items()):
        obs_ids = []
        for f in fs:
            o_uuid = uid("obs", f.image_id, f.vuln_id, f.package)
            obs_ids.append(o_uuid)
            img = v.images_by_id.get(f.image_id)
            desc = (f"{f.vuln_id} ({f.severity}) in package {f.package} {f.installed_version}"
                    + (f", fixed in {f.fixed_version}" if f.fixed_version else ", no fix available")
                    + (f" - image {image_label(img)}" if img else "") + ".")
            props = [_prop("severity", f.severity), _prop("package", f.package or "-"),
                     _prop("fixable", str(bool(f.fixable)).lower())]
            if f.agreement is not None:
                props.append(_prop("agreement", round(f.agreement, 3)))
            if f.cvss is not None:
                props.append(_prop("cvss", f.cvss))
            for s, sv in sorted(f.per_scanner.items()):
                props.append(_prop(f"{s}-severity", sv))
            obs = {
                "uuid": o_uuid, "title": f"{f.vuln_id} in {f.package}", "description": desc, "props": props,
                "methods": ["TEST"], "types": ["finding"],
                "origins": [{"actors": [{"type": "tool", "actor-uuid": scanner_uuid.get(s, tool_uuid)}
                                        for s in (f.scanners or ["pack"])]}],
                "subjects": ([{"subject-uuid": img_uuid[f.image_id], "type": "inventory-item"}]
                             if f.image_id in img_uuid else []),
                "collected": collected,
            }
            if f.url:
                obs["relevant-evidence"] = [{"href": f.url, "description": f"Advisory for {f.vuln_id}"}]
            if not obs["subjects"]:
                del obs["subjects"]
            observations.append(obs)
            for c in f.controls:
                control_obs.setdefault(control_id(c), []).append(o_uuid)
        f0 = max(fs, key=lambda f: sev_rank(f.severity))
        first = min(f.first_seen_at for f in fs)
        r_uuid = uid("risk", vid)
        fixed = sorted({f"{f.package} {f.fixed_version}" for f in fs if f.fixed_version})
        risk = {
            "uuid": r_uuid, "title": f"{vid}: {f0.title}" if f0.title else vid,
            "description": _clean(f0.description or f0.title or vid),
            "statement": (f"{vid} ({f0.severity}) affects {len({f.image_id for f in fs})} image(s). Remediation "
                          f"is due within {v.sla_days.get(f0.severity)} days of first detection "
                          f"({first:%Y-%m-%d})."),
            "props": [_prop("severity", f0.severity), _prop("overdue", str(v.overdue(f0.severity, first)).lower())],
            "status": "open",
            "deadline": iso(v.sla_due(f0.severity, first)),
            "related-observations": [{"observation-uuid": o} for o in obs_ids],
        }
        if fixed:
            risk["remediations"] = [{
                "uuid": uid("remediation", vid), "lifecycle": "planned", "title": "Upgrade affected packages",
                "description": "Rebuild images with: " + "; ".join(fixed) + "; redeploy and rescan.",
            }]
        risks.append(risk)
        for c in {c for f in fs for c in f.controls}:
            control_risks.setdefault(control_id(c), []).append(r_uuid)

    # ---- posture observations / risks
    by_check: dict[str, list] = {}
    for r in v.failed_results:
        by_check.setdefault(r.check_id, []).append(r)
    for cid, rs in sorted(by_check.items()):
        chk = v.check(cid)
        severity = max((r.severity for r in rs), key=sev_rank)
        o_uuid, r_uuid = uid("obs-check", cid), uid("risk-check", cid)
        keys = sorted({r.key for r in rs})
        observations.append({
            "uuid": o_uuid, "title": f"Posture check failed: {chk.title}",
            "description": f"Check '{cid}' failed for {len(keys)} workload(s): " + ", ".join(keys[:50])
                           + (" ..." if len(keys) > 50 else "") + ".",
            "props": [_prop("severity", severity), _prop("check-id", cid)],
            "methods": ["TEST"], "types": ["finding"],
            "origins": [{"actors": [{"type": "tool", "actor-uuid": tool_uuid}]}],
            "subjects": [{"subject-uuid": wl_uuid[k], "type": "inventory-item"} for k in keys],
            "collected": collected,
        })
        first = min((r.first_seen_at for r in rs if r.first_seen_at), default=v.scan.started_at or v.generated_at)
        risks.append({
            "uuid": r_uuid, "title": f"Workload configuration: {chk.title}",
            "description": _clean(chk.description or chk.title),
            "statement": f"{len(keys)} workload(s) fail posture check '{cid}' ({severity}).",
            "props": [_prop("severity", severity)],
            "status": "open",
            "deadline": iso(v.sla_due(severity, first)),
            "related-observations": [{"observation-uuid": o_uuid}],
            **({"remediations": [{"uuid": uid("remediation-check", cid), "lifecycle": "planned",
                                  "title": "Fix workload configuration",
                                  "description": chk.remediation}]} if chk.remediation else {}),
        })
        for c in chk.controls:
            control_obs.setdefault(control_id(c), []).append(o_uuid)
            control_risks.setdefault(control_id(c), []).append(r_uuid)

    # ---- control assertion observations (M3: the same control evidence run as the SSP / POA&M)
    run = v.engine_run
    for r in sorted(v.engine_results, key=lambda r: r.get("id", "")):
        aid = r.get("id", "")
        o_uuid = uid("obs-assertion", aid, run.get("id"))
        status = r.get("status", "unknown")
        observations.append({
            "uuid": o_uuid, "title": f"Control assertion {aid}: {r.get('title', '')}",
            "description": f"{status.upper()}: {_clean(r.get('detail'))}",
            "props": [_prop("assertion-id", aid), _prop("assertion-status", status),
                      _prop("component", r.get("component") or "-"), _prop("control-evidence-run", run.get("id"))],
            "methods": ["TEST"], "types": ["control-objective"],
            "origins": [{"actors": [{"type": "tool", "actor-uuid": tool_uuid}]}],
            "relevant-evidence": [{"href": f"/api/v1/compliance/assertions/{aid}",
                                   "description": "Raw evidence JSON and history of this assertion"}],
            "collected": r.get("checkedAt") or collected,
        })
        for c in r.get("controls") or []:
            control_obs.setdefault(control_id(c), []).append(o_uuid)
            if status == "fail":
                control_fail.add(control_id(c))

    # ---- findings per control: not-satisfied on failing evidence (scan risks, failing assertions or
    # objectives); satisfied only when the control evidence run shows every objective passing (M3)
    engine_status = {control_id(s["control"]): s for s in v.engine_statuses}
    assessed = set(control_obs) | set(control_risks)
    findings = []
    for cid in sorted(assessed):
        obs, rks = control_obs.get(cid, []), control_risks.get(cid, [])
        upper = cid.upper().replace(".", "(", 1) + (")" if "." in cid else "")
        es = engine_status.get(cid) or {}
        bad_obj = [o["id"] for o in es.get("objectives") or [] if o.get("state") == "not-satisfied"]
        if rks or cid in control_fail or bad_obj or es.get("status") == "failing":
            state = "not-satisfied"
        elif es.get("status") == "passing":
            state = "satisfied"
        else:
            continue  # partially evidenced: no determination is made
        fnd = {
            "uuid": uid("finding", cid),
            "title": f"{upper} {control_title(upper)}".strip(),
            "description": (f"{len(rks)} open risk(s) and {len(obs)} observation(s) map to {upper}"
                            + (f"; control evidence status {es['status']}" if es.get("status") else "") + "."),
            "target": {"type": "statement-id", "target-id": f"{cid}_smt", "status": {"state": state}},
        }
        if obs:
            fnd["related-observations"] = [{"observation-uuid": o} for o in dict.fromkeys(obs)]
        if rks:
            fnd["related-risks"] = [{"risk-uuid": r} for r in dict.fromkeys(rks)]
        findings.append(fnd)

    ap_uuid = uid("resource", "assessment-plan")
    result: dict[str, Any] = {
        "uuid": uid("result"),
        "title": f"Automated assessment - scan {v.scan.id}",
        "description": (f"Continuous automated assessment of {v.scope_label}: {len(v.images)} image(s) scanned by "
                        f"{', '.join(SCANNER_TITLES.get(s.name, s.name) for s in v.scanners) or 'configured scanners'}"
                        f" and {len(v.posture_results)} posture check evaluation(s); {v.run_stamp}. Hygiene index "
                        f"{v.scan.score if v.scan.score is not None else 'n/a'} (grade {v.scan.grade})."),
        "start": iso(v.scan.started_at or v.generated_at),
        "local-definitions": {"components": components, **({"inventory-items": inventory} if inventory else {})},
        "props": [_prop("scan-id", v.scan.id), _prop("control-evidence-run", v.engine_run.get("id") or "none"),
                  _prop("hygiene-grade", v.scan.grade or "?")]
                 + ([_prop("hygiene-index", v.scan.score)] if v.scan.score is not None else []),
        "reviewed-controls": {"control-selections": [{
            "description": "NIST SP 800-53 Rev. 5 controls with automated evidence (scans, posture checks and "
                           "control assertions).",
            "include-controls": [{"control-id": c} for c in sorted(assessed or {"ra-5"})],
        }]},
    }
    if v.scan.finished_at:
        result["end"] = iso(v.scan.finished_at)
    if observations:
        result["observations"] = observations
    if risks:
        result["risks"] = risks
    if findings:
        result["findings"] = findings

    parties = [{"uuid": uid("party", "org"), "type": "organization",
                "name": v.system.organization or v.system.name}]
    if v.system.poc_name:
        party = {"uuid": uid("party", "poc"), "type": "person", "name": v.system.poc_name}
        if v.system.poc_email:
            party["email-addresses"] = [v.system.poc_email]
        parties.append(party)

    return {"assessment-results": {
        "uuid": uid("ar"),
        "metadata": {
            "title": f"{v.system.name} - Assessment Results (scan {v.scan.id})",
            "last-modified": iso(v.generated_at),
            "version": str(v.scan.id),
            "oscal-version": OSCAL_VERSION,
            "props": [_prop("system-name", v.system.name), _prop("scope", v.scope_label),
                      _prop("generator", TOOL_NAME)],
            "parties": parties,
        },
        "import-ap": {"href": f"#{ap_uuid}"},
        "results": [result],
        "back-matter": {"resources": [{
            "uuid": ap_uuid, "title": "Implicit assessment plan",
            "description": "Continuous automated assessment: image inventory from the Kubernetes API, "
                           "vulnerability scanning with Trivy, Grype and Clair (consensus by vulnerability "
                           "and package), and Kubernetes workload posture checks, run on a schedule by "
                           f"{TOOL_NAME}. No separate OSCAL assessment-plan document exists.",
        }]},
    }}


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    data = json.dumps(build(v), indent=2, ensure_ascii=False).encode("utf-8")
    return GeneratedReport(data, filename(v, "oscal-ar", "json"), "application/json")
