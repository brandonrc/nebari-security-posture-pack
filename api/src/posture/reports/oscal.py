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

import base64
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
    # objective id -> evidence (S3: findings target SP 800-53A objectives, not whole controls)
    objective: dict[str, dict[str, Any]] = {}

    def touch(obj_id: str, *, bad: bool = False, good: bool = False, obs: str | None = None,
              risk: str | None = None) -> None:
        e = objective.setdefault(obj_id, {"bad": False, "good": False, "obs": [], "risks": []})
        e["bad"] |= bad
        e["good"] |= good
        if obs and obs not in e["obs"]:
            e["obs"].append(obs)
        if risk and risk not in e["risks"]:
            e["risks"].append(risk)

    def objectives_for(control: str, kind: str) -> list[str]:
        """Objectives scan evidence counts against (controls.yaml scanObjectives; else all of the control)."""
        from ..controls import scan_objectives
        from ..controls_engine.catalog import get_catalog

        cat = get_catalog().get(control)
        if cat is None:
            return []
        refs = scan_objectives(kind, cat.label)
        return cat.expand_objectives(refs) if refs else list(cat.objective_ids)

    # ---- vulnerability observations, grouped per image (S3: tens, not tens of thousands)
    by_image: dict[Any, list] = {}
    for f in v.open_findings:
        by_image.setdefault(f.image_id, []).append(f)
    image_obs: dict[Any, str] = {}
    for image_id, fs in sorted(by_image.items(), key=lambda kv: str(kv[0])):
        img = v.images_by_id.get(image_id)
        o_uuid = uid("obs-image", image_id)
        image_obs[image_id] = o_uuid
        sevc: dict[str, int] = {}
        for f in fs:
            sevc[f.severity] = sevc.get(f.severity, 0) + 1
        ids = sorted({f.vuln_id for f in fs}, key=lambda i: (-max(sev_rank(f.severity) for f in fs if f.vuln_id == i), i))
        kev = sorted({f.vuln_id for f in fs if f.kev})
        props = [_prop("findings", len(fs)), *[_prop(f"findings-{k}", n) for k, n in sorted(sevc.items())],
                 _prop("fixable", sum(1 for f in fs if f.fixable)), _prop("known-exploited", len(kev))]
        obs = {
            "uuid": o_uuid, "title": f"Vulnerabilities in {image_label(img) if img else image_id}",
            "description": (f"{len(fs)} open finding(s), {len(ids)} vulnerability ID(s): " + ", ".join(ids[:200])
                            + (f" ... +{len(ids) - 200} more (see vuln-export)" if len(ids) > 200 else "")
                            + (f". CISA KEV: {', '.join(kev)}" if kev else "") + "."),
            "props": props, "methods": ["TEST"], "types": ["finding"],
            "origins": [{"actors": [{"type": "tool", "actor-uuid": scanner_uuid.get(sn, tool_uuid)}
                                    for sn in sorted({sn for f in fs for sn in f.scanners}) or ["pack"]]}],
            "collected": collected,
        }
        if image_id in img_uuid:
            obs["subjects"] = [{"subject-uuid": img_uuid[image_id], "type": "inventory-item"}]
        observations.append(obs)

    by_vuln: dict[str, list] = {}
    for f in v.open_findings:
        by_vuln.setdefault(f.vuln_id, []).append(f)
    for vid, fs in sorted(by_vuln.items()):
        f0 = max(fs, key=lambda f: sev_rank(f.severity))
        first = min(f.first_seen_at for f in fs)
        due = min((d for d in (v.finding_due(f) for f in fs) if d), default=None)
        overdue = bool(due and due < v.now)
        r_uuid = uid("risk", vid)
        fixed = sorted({f"{f.package} {f.fixed_version}" for f in fs if f.fixed_version})
        kev = any(f.kev for f in fs)
        facets = [{"name": "severity", "system": NS, "value": f0.severity},
                  {"name": "known-exploited", "system": NS, "value": str(kev).lower()},
                  {"name": "likelihood", "system": NS, "value": "not-assessed"},
                  {"name": "impact", "system": NS, "value": "not-assessed"}]
        cvss = max((f.cvss for f in fs if f.cvss is not None), default=None)
        if cvss is not None:
            facets.append({"name": "cvss-base-score", "system": NS, "value": str(cvss)})
        obs_ids = list(dict.fromkeys(image_obs[f.image_id] for f in fs if f.image_id in image_obs))
        risk = {
            "uuid": r_uuid, "title": f"{vid}: {f0.title}" if f0.title else vid,
            "description": _clean(f0.description or f0.title or vid),
            "statement": (f"{vid} ({f0.severity}) affects {len({f.image_id for f in fs})} image(s). Remediation "
                          f"is due by {due:%Y-%m-%d} (severity SLA from first detection {first:%Y-%m-%d}"
                          + (", or the CISA KEV due date" if kev else "") + ")." if due else
                          f"{vid} ({f0.severity}) affects {len({f.image_id for f in fs})} image(s)."),
            "props": [_prop("severity", f0.severity), _prop("overdue", str(overdue).lower()),
                      _prop("known-exploited", str(kev).lower())],
            "status": "open",
            "characterizations": [{"origin": {"actors": [{"type": "tool", "actor-uuid": tool_uuid}]},
                                   "facets": facets}],
            "deadline": iso(due),
            "related-observations": [{"observation-uuid": o} for o in obs_ids],
            "risk-log": {"entries": [{"uuid": uid("risk-log", vid), "title": "Identified by automated scanning",
                                      "start": iso(first), "status-change": "open"}]},
        }
        if not risk["related-observations"]:
            del risk["related-observations"]
        if fixed:
            risk["remediations"] = [{
                "uuid": uid("remediation", vid), "lifecycle": "planned", "title": "Upgrade affected packages",
                "description": "Rebuild images with: " + "; ".join(fixed) + "; redeploy and rescan.",
            }]
        risks.append(risk)
        for c in {c for f in fs for c in f.controls}:
            for kind in ("open", *(("overdue",) if overdue else ())):
                for o in objectives_for(c, kind):
                    touch(o, bad=True, risk=r_uuid, obs=obs_ids[0] if obs_ids else None)

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
            "characterizations": [{"origin": {"actors": [{"type": "tool", "actor-uuid": tool_uuid}]},
                                   "facets": [{"name": "severity", "system": NS, "value": severity},
                                              {"name": "likelihood", "system": NS, "value": "not-assessed"},
                                              {"name": "impact", "system": NS, "value": "not-assessed"}]}],
            "deadline": iso(v.sla_due(severity, first)),
            "related-observations": [{"observation-uuid": o_uuid}],
            **({"remediations": [{"uuid": uid("remediation-check", cid), "lifecycle": "planned",
                                  "title": "Fix workload configuration",
                                  "description": chk.remediation}]} if chk.remediation else {}),
        })
        for c in chk.controls:
            for o in objectives_for(c, "posture"):
                touch(o, bad=True, obs=o_uuid, risk=r_uuid)

    # ---- control assertion observations (M3: the same control evidence run as the SSP / POA&M)
    run = v.engine_run
    assertion_obs: dict[str, str] = {}
    for r in sorted(v.engine_results, key=lambda r: r.get("id", "")):
        aid = r.get("id", "")
        o_uuid = uid("obs-assertion", aid, run.get("id"))
        assertion_obs[aid] = o_uuid
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
    for st in v.engine_statuses:
        for o in st.get("objectives") or []:
            if o.get("state") not in ("satisfied", "not-satisfied"):
                continue
            real = [a for a in o.get("assertions") or [] if a in assertion_obs]
            for a in real or [None]:
                touch(o["id"], bad=o["state"] == "not-satisfied", good=o["state"] == "satisfied",
                      obs=assertion_obs.get(a) if a else None)

    # ---- findings per SP 800-53A objective (S3): not-satisfied on any failing evidence, satisfied only
    # when the control evidence run shows passing evidence and nothing fails; nothing else is determined
    from ..controls_engine.catalog import objective_control

    findings = []
    for oid in sorted(objective):
        e = objective[oid]
        if not (e["bad"] or e["good"]):
            continue
        state = "not-satisfied" if e["bad"] else "satisfied"
        label = objective_control(oid).upper()
        label = label.replace(".", "(", 1) + (")" if "." in label else "")
        fnd = {
            "uuid": uid("finding", oid),
            "title": f"{label} objective {oid.split('_obj', 1)[1].lstrip('.-') or '(whole control)'}: "
                     f"{control_title(label)}".strip(),
            "description": (f"{len(e['risks'])} open risk(s) and {len(e['obs'])} observation(s) bear on "
                            f"SP 800-53A objective {oid}."),
            "target": {"type": "objective-id", "target-id": oid, "status": {"state": state}},
        }
        if e["obs"]:
            fnd["related-observations"] = [{"observation-uuid": o} for o in e["obs"]]
        if e["risks"]:
            fnd["related-risks"] = [{"risk-uuid": r} for r in e["risks"]]
        findings.append(fnd)
    assessed = {objective_control(o) for o in objective} or {"ra-5"}

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
            "include-controls": [{"control-id": c} for c in sorted(assessed)],
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
            "uuid": ap_uuid, "title": "Assessment plan (automated continuous monitoring)",
            "description": "Minimal OSCAL assessment-plan for the automated assessment: the reviewed controls, "
                           "the assessment subjects (every inventoried image and workload) and the tools. Embedded "
                           "below; replace this resource with your assessment plan when an assessor uses one.",
            "props": [_prop("document-type", "assessment-plan")],
            "base64": {"filename": "assessment-plan.json", "media-type": "application/json",
                       "value": base64.b64encode(json.dumps({"assessment-plan": assessment_plan(
                           v, uid, sorted(assessed), components, inventory, parties)}).encode()).decode()},
        }]},
    }}


def assessment_plan(v: View, uid: Any, controls: list[str], components: list[dict[str, Any]],
                    inventory: list[dict[str, Any]], parties: list[dict[str, Any]]) -> dict[str, Any]:
    """A real, minimal OSCAL 1.1.2 assessment-plan (S3) so tools that resolve import-ap find one."""
    ap: dict[str, Any] = {
        "uuid": uid("assessment-plan"),
        "metadata": {"title": f"{v.system.name} - automated continuous-monitoring assessment plan",
                     "last-modified": iso(v.generated_at), "version": str(v.scan.id), "oscal-version": OSCAL_VERSION,
                     "parties": parties},
        "import-ssp": {"href": filename(v, "oscal-ssp", "json"),
                       "remarks": "The OSCAL SSP generated from the same scan and control evidence run."},
        "local-definitions": {"components": components,
                              "activities": [{"uuid": uid("activity", "scan"), "title": "Automated scan",
                                              "description": "Image inventory, three-scanner vulnerability "
                                                             "consensus, workload posture checks and live control "
                                                             "assertions, on a schedule and on demand."}]},
        "reviewed-controls": {"control-selections": [{"include-controls": [{"control-id": c} for c in controls]}]},
        "assessment-subjects": [{"type": "inventory-item", "include-all": {}}],
    }
    if inventory:
        ap["local-definitions"]["inventory-items"] = inventory
    return ap


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    data = json.dumps(build(v), indent=2, ensure_ascii=False).encode("utf-8")
    return GeneratedReport(data, filename(v, "oscal-ar", "json"), "application/json")
