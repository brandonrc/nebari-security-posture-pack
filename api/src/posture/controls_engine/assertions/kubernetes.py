"""Kubernetes platform assertions (Pod Security, NetworkPolicy, RBAC, versions, audit)."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Any

from ..context import EngineContext
from ..model import Result, assertion, failed, not_applicable, passed, unknown

C = "kubernetes"
PSA_ENFORCE = "pod-security.kubernetes.io/enforce"
PSA_OK = ("baseline", "restricted")
ANON_SUBJECTS = {("User", "system:anonymous"), ("Group", "system:unauthenticated")}
# Upstream bindings that intentionally expose public, non-sensitive discovery information.
ANON_ALLOWED_ROLES = {"system:public-info-viewer", "kubeadm:bootstrap-signer-clusterinfo"}
# Upstream end-of-life dates (https://kubernetes.io/releases/patch-releases/); minors newer than
# the table are treated as supported, older ones as end of life.
K8S_EOL = {27: date(2024, 6, 28), 28: date(2024, 10, 28), 29: date(2025, 2, 28), 30: date(2025, 6, 28),
           31: date(2025, 10, 28), 32: date(2026, 2, 28), 33: date(2026, 6, 28), 34: date(2026, 10, 27),
           35: date(2027, 2, 28), 36: date(2027, 6, 28)}
LEAST_PRIVILEGE_CHECKS = ("privileged", "host-namespaces", "added-capabilities", "host-path", "privilege-escalation")


def _active_pod_namespaces(pods: list[dict[str, Any]]) -> set[str]:
    return {p["metadata"]["namespace"] for p in pods
            if (p.get("status") or {}).get("phase") not in ("Succeeded", "Failed")}


@assertion(id="k8s-pod-security-admission", title="Namespaces enforce a Pod Security Standard",
           controls=["CM-6", "CM-7"], component=C, severity="high")
async def pod_security(ctx: EngineContext) -> Result:
    """Every non-system namespace carries `pod-security.kubernetes.io/enforce` = baseline or restricted."""
    nss = await ctx.app_namespaces()
    levels: dict[str, str | None] = {n["metadata"]["name"]: (n["metadata"].get("labels") or {}).get(PSA_ENFORCE)
                                     for n in nss}
    bad = sorted(ns for ns, lvl in levels.items() if lvl not in PSA_OK)
    ev = {"namespaces": len(levels), "enforced": {ns: lvl for ns, lvl in levels.items() if lvl in PSA_OK},
          "notEnforced": {ns: levels[ns] for ns in bad}, "systemNamespaces": ctx.config.system_namespaces}
    if not levels:
        return not_applicable("no non-system namespaces", **ev)
    if bad:
        return failed(f"{len(bad)} of {len(levels)} namespace(s) without baseline/restricted enforcement: "
                      + ", ".join(bad[:12]) + ("…" if len(bad) > 12 else ""), **ev)
    return passed(f"all {len(levels)} non-system namespace(s) enforce baseline or restricted", **ev)


def is_default_deny_ingress(np: dict[str, Any]) -> bool:
    spec = np.get("spec") or {}
    sel = spec.get("podSelector") or {}
    if sel.get("matchLabels") or sel.get("matchExpressions"):
        return False
    types = spec.get("policyTypes") or ["Ingress"]
    return "Ingress" in types


@assertion(id="k8s-default-deny-ingress", title="Each app namespace has a default-deny ingress NetworkPolicy",
           controls=["SC-7", "SC-7(5)"], component=C, severity="high")
async def default_deny(ctx: EngineContext) -> Result:
    """Every non-system namespace with pods has a NetworkPolicy selecting all pods (`podSelector: {}`)
    for Ingress, so traffic not explicitly allowed is denied."""
    app_ns = {n["metadata"]["name"] for n in await ctx.app_namespaces()}
    with_pods = sorted(app_ns & _active_pod_namespaces(await ctx.pods()))
    nps = await ctx.k8s_list("/apis/networking.k8s.io/v1/networkpolicies")
    deny: dict[str, list[str]] = {}
    for np in nps:
        if is_default_deny_ingress(np):
            deny.setdefault(np["metadata"]["namespace"], []).append(np["metadata"]["name"])
    missing = [ns for ns in with_pods if ns not in deny]
    ev = {"namespacesWithPods": len(with_pods), "defaultDeny": {ns: deny[ns] for ns in with_pods if ns in deny},
          "missing": missing}
    if not with_pods:
        return not_applicable("no application namespaces with pods", **ev)
    if missing:
        return failed(f"{len(missing)} of {len(with_pods)} namespace(s) without default-deny ingress: "
                      + ", ".join(missing[:12]) + ("…" if len(missing) > 12 else ""), **ev)
    return passed(f"all {len(with_pods)} application namespace(s) have default-deny ingress", **ev)


def subject_label(s: dict[str, Any]) -> str:
    if s.get("kind") == "ServiceAccount":
        return f"ServiceAccount:{s.get('namespace', '')}/{s.get('name')}"
    return f"{s.get('kind')}:{s.get('name')}"


def subject_allowed(s: dict[str, Any], allow: list[str]) -> bool:
    label = subject_label(s)
    return label in allow or s.get("name") in allow or (s.get("kind") == "ServiceAccount" and
                                                        f"{s.get('namespace')}/{s.get('name')}" in allow)


def is_system_subject(s: dict[str, Any]) -> bool:
    name = s.get("name") or ""
    return name.startswith("system:") and s.get("kind") in ("User", "Group")


@assertion(id="k8s-cluster-admin-bindings", title="cluster-admin bound only to system or approved subjects",
           controls=["AC-6(1)"], component=C, severity="critical")
async def cluster_admin(ctx: EngineContext) -> Result:
    """ClusterRoleBindings to `cluster-admin` have only `system:*` users/groups or subjects listed in
    `controlsEngine.adminSubjects` (`User:alice`, `Group:ops`, `ServiceAccount:ns/name`)."""
    crbs = await ctx.k8s_list("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
    bindings, extra = [], []
    for b in crbs:
        rr = b.get("roleRef") or {}
        if rr.get("kind") != "ClusterRole" or rr.get("name") != "cluster-admin":
            continue
        subs = b.get("subjects") or []
        bindings.append({"binding": b["metadata"]["name"], "subjects": [subject_label(s) for s in subs]})
        for s in subs:
            if not is_system_subject(s) and not subject_allowed(s, ctx.config.admin_subjects):
                extra.append({"binding": b["metadata"]["name"], "subject": subject_label(s)})
    ev = {"clusterAdminBindings": bindings, "notAllowlisted": extra, "allowlist": ctx.config.admin_subjects}
    if extra:
        return failed(f"{len(extra)} non-system subject(s) bound to cluster-admin: "
                      + ", ".join(e["subject"] for e in extra[:10]), **ev)
    return passed(f"{len(bindings)} cluster-admin binding(s); only system or approved subjects", **ev)


@assertion(id="k8s-default-sa-automount", title="Default ServiceAccounts do not automount API tokens",
           controls=["AC-6(10)"], component=C, severity="medium")
async def default_sa(ctx: EngineContext) -> Result:
    """The `default` ServiceAccount of every non-system namespace sets `automountServiceAccountToken: false`."""
    app_ns = {n["metadata"]["name"] for n in await ctx.app_namespaces()}
    sas = await ctx.k8s_list("/api/v1/serviceaccounts")
    rows = {sa["metadata"]["namespace"]: sa.get("automountServiceAccountToken") for sa in sas
            if sa["metadata"]["name"] == "default" and sa["metadata"]["namespace"] in app_ns}
    bad = sorted(ns for ns, v in rows.items() if v is not False)
    ev = {"checked": len(rows), "automounting": bad}
    if not rows:
        return not_applicable("no default ServiceAccounts in non-system namespaces", **ev)
    if bad:
        return failed(f"{len(bad)} of {len(rows)} default ServiceAccount(s) automount tokens: "
                      + ", ".join(bad[:12]) + ("…" if len(bad) > 12 else ""), **ev)
    return passed(f"all {len(rows)} default ServiceAccount(s) disable token automount", **ev)


@assertion(id="k8s-no-anonymous-access", title="No RBAC grants to anonymous/unauthenticated users",
           controls=["AC-14"], component=C, severity="critical")
async def anonymous(ctx: EngineContext) -> Result:
    """No (Cluster)RoleBinding grants a role to `system:anonymous` or `system:unauthenticated`,
    except upstream public discovery roles (`system:public-info-viewer`)."""
    crbs = await ctx.k8s_list("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
    rbs = await ctx.k8s_list("/apis/rbac.authorization.k8s.io/v1/rolebindings")
    allowed, bad = [], []
    for b in [*crbs, *rbs]:
        subs = [s for s in b.get("subjects") or [] if (s.get("kind"), s.get("name")) in ANON_SUBJECTS]
        if not subs:
            continue
        name = f"{b['metadata'].get('namespace', '')}/{b['metadata']['name']}".lstrip("/")
        row = {"binding": name, "role": (b.get("roleRef") or {}).get("name"),
               "subjects": [s["name"] for s in subs]}
        (allowed if row["role"] in ANON_ALLOWED_ROLES else bad).append(row)
    ev = {"publicDiscovery": allowed, "offending": bad}
    if bad:
        return failed(f"{len(bad)} binding(s) grant access to anonymous users: "
                      + ", ".join(f"{b['binding']}→{b['role']}" for b in bad[:10]), **ev)
    return passed("no anonymous grants beyond public discovery" + (f" ({len(allowed)} upstream)" if allowed else ""),
                  **ev)


def _minor(version: str) -> int | None:
    m = re.match(r"^v?(\d+)\.(\d+)", version or "")
    return int(m.group(2)) if m and m.group(1) == "1" else None


@assertion(id="k8s-supported-version", title="Kubernetes version is still supported upstream", controls=["SI-2"],
           component=C, severity="high")
async def supported_version(ctx: EngineContext) -> Result:
    """API server and every kubelet run a Kubernetes minor version before its upstream end-of-life date."""
    today = datetime.now(UTC).date()
    server = (await ctx.k8s_get("/version")).get("gitVersion", "")
    nodes = await ctx.k8s_list("/api/v1/nodes")
    versions = {"apiserver": server, **{f"node/{n['metadata']['name']}": (n.get("status") or {}).get(
        "nodeInfo", {}).get("kubeletVersion", "") for n in nodes}}
    rows, bad = [], []
    lo = min(K8S_EOL)
    for who, v in versions.items():
        mi = _minor(v)
        eol = K8S_EOL.get(mi) if mi is not None else None
        if mi is None:
            status = "unparseable"
        elif mi < lo or (eol and eol < today):
            status = "end-of-life"
        else:
            status = "supported"
        row = {"component": who, "version": v, "endOfLife": eol.isoformat() if eol else None,
               "status": status}
        rows.append(row)
        if status != "supported":
            bad.append(row)
    if bad:
        return failed("unsupported Kubernetes: " + ", ".join(f"{b['component']} {b['version']} ({b['status']})"
                                                            for b in bad[:5]), versions=rows)
    eols = sorted({r["endOfLife"] for r in rows if r["endOfLife"]})
    return passed(f"Kubernetes {server} supported" + (f" until {eols[0]}" if eols else ""), versions=rows)


@assertion(id="k8s-api-audit-logging", title="Kubernetes API server audit logging is enabled",
           controls=["AU-2", "AU-12"], component=C, severity="high")
async def api_audit(ctx: EngineContext) -> Result:
    """A visible kube-apiserver pod runs with `--audit-policy-file` and a log or webhook backend.
    Managed / snap / systemd control planes do not expose their flags: the result is `unknown`."""
    pods = [p for p in await ctx.pods() if p["metadata"]["namespace"] == "kube-system"
            and ((p["metadata"].get("labels") or {}).get("component") == "kube-apiserver"
                 or p["metadata"]["name"].startswith("kube-apiserver"))]
    if not pods:
        return unknown("the API server is not visible as a pod (managed, snap or systemd control plane); "
                       "verify audit logging on the control-plane hosts and attach that evidence manually")
    rows, bad = [], []
    for p in pods:
        args: list[str] = []
        for c in (p.get("spec") or {}).get("containers") or []:
            args += [*(c.get("command") or []), *(c.get("args") or [])]
        flags = {a.split("=", 1)[0]: (a.split("=", 1)[1] if "=" in a else "") for a in args if a.startswith("--audit")}
        ok = "--audit-policy-file" in flags and ("--audit-log-path" in flags or "--audit-webhook-config-file" in flags)
        rows.append({"pod": p["metadata"]["name"], "auditFlags": flags, "enabled": ok})
        if not ok:
            bad.append(p["metadata"]["name"])
    if bad:
        return failed("API server audit logging not configured on " + ", ".join(bad), apiservers=rows)
    return passed(f"audit policy + backend configured on {len(rows)} API server pod(s)", apiservers=rows)


@assertion(id="k8s-workload-least-privilege", title="Workloads avoid privileged settings",
           controls=["AC-6", "CM-7"], component=C, severity="high")
async def workload_least_privilege(ctx: EngineContext) -> Result:
    """From the latest scan's posture checks: no non-system workload fails `privileged`,
    `host-namespaces`, `host-path`, `added-capabilities` or `privilege-escalation`."""
    snap = ctx.snapshot
    if snap is None:
        return unknown("scan evidence unavailable (posture database not readable)")
    if not snap.get("lastDoneScan"):
        return unknown("no completed scan yet (posture checks unavailable)")
    fails = [f for f in snap.get("postureFailures") or [] if f.get("checkId") in LEAST_PRIVILEGE_CHECKS
             and not ctx.is_system_namespace(f.get("namespace", ""))]
    by_check: dict[str, int] = {}
    workloads = sorted({f"{f['namespace']}/{f['kind']}/{f['name']}" for f in fails})
    for f in fails:
        by_check[f["checkId"]] = by_check.get(f["checkId"], 0) + 1
    ev = {"scanId": snap["lastDoneScan"].get("id"), "failuresByCheck": by_check, "workloads": workloads[:100],
          "workloadCount": len(workloads)}
    if fails:
        return failed(f"{len(workloads)} workload(s) fail least-privilege checks ("
                      + ", ".join(f"{k}: {v}" for k, v in sorted(by_check.items())) + ")", **ev)
    return passed(f"no non-system workload fails least-privilege checks (scan {ev['scanId']})", **ev)
