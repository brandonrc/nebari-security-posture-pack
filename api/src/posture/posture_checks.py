"""Kubernetes posture (configuration) checks per docs/SCORING.md. Pure functions."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .controls import check_controls
from .controls_engine.exceptions import ACCEPTED_RISK, find as find_exception
from .images import has_mutable_tag
from .inventory_model import ContainerRecord, InventorySnapshot, selector_matches
from .scoring import SYSTEM_NAMESPACES, check_weight, posture_score

DANGEROUS_CAPS = frozenset({
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "BPF", "PERFMON",
    "SYS_BOOT", "DAC_READ_SEARCH", "SYS_TIME",
})
BATCH_KINDS = frozenset({"Job", "CronJob"})


@dataclass(frozen=True)
class CheckDef:
    id: str
    title: str
    severity: str
    category: str
    scope: str  # container | pod
    description: str
    remediation: str

    @property
    def controls(self) -> list[str]:
        return check_controls(self.id)


CHECKS: list[CheckDef] = [
    CheckDef("privileged", "Privileged container", "critical", "privilege", "container",
             "Container runs with securityContext.privileged: true and has full access to the host.",
             "Remove `privileged: true`; grant only the specific capabilities required."),
    CheckDef("host-namespaces", "Host namespaces shared", "critical", "isolation", "pod",
             "Pod sets hostPID, hostIPC or hostNetwork and shares the node's namespaces.",
             "Set hostPID, hostIPC and hostNetwork to false (the default)."),
    CheckDef("host-path", "hostPath volume", "high", "isolation", "pod",
             "Pod mounts a hostPath volume, exposing the node filesystem.",
             "Use PersistentVolumeClaims, ConfigMaps, Secrets or emptyDir instead of hostPath."),
    CheckDef("run-as-root", "May run as root", "high", "privilege", "container",
             "Neither container nor pod sets runAsNonRoot: true and runAsUser is unset or 0.",
             "Set `securityContext.runAsNonRoot: true` and a non-zero `runAsUser`."),
    CheckDef("privilege-escalation", "Privilege escalation allowed", "high", "privilege", "container",
             "allowPrivilegeEscalation is not explicitly false (setuid binaries can gain privileges).",
             "Set `securityContext.allowPrivilegeEscalation: false`."),
    CheckDef("added-capabilities", "Linux capabilities added", "high", "privilege", "container",
             "securityContext.capabilities.add is non-empty (SYS_ADMIN/NET_ADMIN etc. are critical).",
             "Remove added capabilities; if unavoidable add only narrowly scoped ones (e.g. NET_BIND_SERVICE)."),
    CheckDef("capabilities-not-dropped", "Capabilities not dropped", "medium", "privilege", "container",
             "securityContext.capabilities.drop does not contain ALL.",
             "Set `securityContext.capabilities.drop: [\"ALL\"]` and add back only what is needed."),
    CheckDef("writable-rootfs", "Writable root filesystem", "medium", "hardening", "container",
             "readOnlyRootFilesystem is not true.",
             "Set `securityContext.readOnlyRootFilesystem: true`; mount emptyDir for scratch paths."),
    CheckDef("no-resource-limits", "No resource limits", "medium", "resources", "container",
             "CPU or memory limits are unset.",
             "Set `resources.limits.cpu` and `resources.limits.memory`."),
    CheckDef("no-resource-requests", "No resource requests", "low", "resources", "container",
             "CPU or memory requests are unset.",
             "Set `resources.requests.cpu` and `resources.requests.memory`."),
    CheckDef("mutable-tag", "Mutable image tag", "medium", "supply-chain", "container",
             "Image uses `:latest` or no tag and is not pinned by digest.",
             "Pin images to an immutable version tag, ideally `image@sha256:<digest>`."),
    CheckDef("no-liveness-probe", "No liveness probe", "low", "reliability", "container",
             "Long-running container has no livenessProbe.",
             "Add a `livenessProbe` so hung containers are restarted."),
    CheckDef("no-readiness-probe", "No readiness probe", "low", "reliability", "container",
             "Long-running container has no readinessProbe.",
             "Add a `readinessProbe` so traffic only reaches ready containers."),
    CheckDef("automount-sa-token", "Default SA token automounted", "low", "identity", "pod",
             "Pod uses the `default` ServiceAccount and automountServiceAccountToken is not false.",
             "Set `automountServiceAccountToken: false` or use a dedicated ServiceAccount."),
    CheckDef("seccomp-unconfined", "Seccomp unconfined", "medium", "hardening", "container",
             "seccompProfile type is Unconfined, or unset at both pod and container level.",
             "Set `securityContext.seccompProfile.type: RuntimeDefault`."),
    CheckDef("no-netpol", "No NetworkPolicy", "low", "network", "pod",
             "No NetworkPolicy in the namespace selects this pod.",
             "Add a NetworkPolicy that selects the pod and restricts ingress/egress."),
]
CHECKS_BY_ID = {c.id: c for c in CHECKS}


@dataclass
class CheckResult:
    check_id: str
    namespace: str
    kind: str
    name: str
    container: str  # "" for pod-scoped checks
    status: str  # pass | fail | accepted-risk (failing, covered by an active risk acceptance; no penalty)
    detail: str
    severity: str  # effective severity (added-capabilities may escalate)
    weight: float
    system_namespace: bool
    pod: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "checkId": self.check_id,
            "namespace": self.namespace,
            "kind": self.kind,
            "name": self.name,
            "container": self.container,
            "pod": self.pod,
            "status": self.status,
            "detail": self.detail,
            "severity": self.severity,
            "weight": self.weight,
            "systemNamespace": self.system_namespace,
        }


Outcome = tuple[bool, str] | tuple[bool, str, str] | None  # (failed, detail[, severity]) or None (n/a)


def _sc(c: ContainerRecord) -> dict[str, Any]:
    return (c.security.get("container") or {}).get("securityContext") or {}


def _psc(c: ContainerRecord) -> dict[str, Any]:
    return (c.security.get("pod") or {}).get("securityContext") or {}


def _long_running(c: ContainerRecord) -> bool:
    if c.container_type == "container":
        return c.workload_kind not in BATCH_KINDS
    # native sidecars (init containers with restartPolicy Always) are long-running
    return c.container_type == "init" and (c.security.get("container") or {}).get("restartPolicy") == "Always"


def _windows(c: ContainerRecord) -> bool:
    return (c.security.get("pod") or {}).get("os") == "windows"


def linux_only(fn: Callable[[ContainerRecord], Outcome]) -> Callable[[ContainerRecord], Outcome]:
    """Fields the kubelet ignores (or the API rejects) on Windows pods: not applicable there."""
    def wrapped(c: ContainerRecord) -> Outcome:
        return None if _windows(c) else fn(c)
    wrapped.__name__ = fn.__name__
    return wrapped


def check_privileged(c: ContainerRecord) -> Outcome:
    if (c.security.get("container") or {}).get("hostProcess") is True:
        return True, "windowsOptions.hostProcess: true (runs as a host process on the node)"
    return (_sc(c).get("privileged") is True, "privileged: true" if _sc(c).get("privileged") else "not privileged")


def check_run_as_root(c: ContainerRecord) -> Outcome:
    sc, psc = _sc(c), _psc(c)
    if _windows(c):
        # runAsUser/runAsGroup do not exist on Windows; only an explicit ContainerAdministrator
        # (or runAsNonRoot) says anything about the user.
        if (sc.get("runAsNonRoot") if sc.get("runAsNonRoot") is not None else psc.get("runAsNonRoot")) is True:
            return False, "runAsNonRoot: true"
        user = ((sc.get("windowsOptions") or {}).get("runAsUserName")
                or (psc.get("windowsOptions") or {}).get("runAsUserName"))
        if user is None:
            return None
        return (user.lower() == "containeradministrator", f"windowsOptions.runAsUserName: {user}")
    non_root = sc.get("runAsNonRoot") if sc.get("runAsNonRoot") is not None else psc.get("runAsNonRoot")
    user = sc.get("runAsUser") if sc.get("runAsUser") is not None else psc.get("runAsUser")
    if non_root is True:
        return False, "runAsNonRoot: true"
    if user not in (None, 0):
        return False, f"runAsUser: {user}"
    return True, ("runAsNonRoot is false" if non_root is False else "runAsNonRoot not set") \
        + " and runAsUser " + ("is 0" if user == 0 else "unset")


def check_privilege_escalation(c: ContainerRecord) -> Outcome:
    v = _sc(c).get("allowPrivilegeEscalation")
    return (v is not False, f"allowPrivilegeEscalation: {'unset' if v is None else str(v).lower()}")


def check_added_capabilities(c: ContainerRecord) -> Outcome:
    added = [str(x).upper().removeprefix("CAP_") for x in ((_sc(c).get("capabilities") or {}).get("add") or [])]
    if not added:
        return False, "no capabilities added"
    dangerous = sorted(set(added) & DANGEROUS_CAPS)
    sev = "critical" if dangerous else "high"
    return True, "capabilities.add: " + ", ".join(added), sev


def check_caps_dropped(c: ContainerRecord) -> Outcome:
    drop = [str(x).upper() for x in ((_sc(c).get("capabilities") or {}).get("drop") or [])]
    return ("ALL" not in drop, "capabilities.drop: " + (", ".join(drop) if drop else "none"))


def check_writable_rootfs(c: ContainerRecord) -> Outcome:
    v = _sc(c).get("readOnlyRootFilesystem")
    return (v is not True, f"readOnlyRootFilesystem: {'unset' if v is None else str(v).lower()}")


def _resources(c: ContainerRecord) -> dict[str, Any]:
    return (c.security.get("container") or {}).get("resources") or {}


def check_limits(c: ContainerRecord) -> Outcome:
    limits = _resources(c).get("limits") or {}
    missing = [r for r in ("cpu", "memory") if not limits.get(r)]
    return (bool(missing), "missing limits: " + ", ".join(missing) if missing else "cpu and memory limits set")


def check_requests(c: ContainerRecord) -> Outcome:
    req = _resources(c).get("requests") or {}
    missing = [r for r in ("cpu", "memory") if not req.get(r)]
    return (bool(missing), "missing requests: " + ", ".join(missing) if missing else "cpu and memory requests set")


def check_mutable_tag(c: ContainerRecord) -> Outcome:
    mutable = has_mutable_tag(c.image)
    return (mutable, f"image {c.image} " + ("uses a mutable tag" if mutable else "is pinned"))


def check_liveness(c: ContainerRecord) -> Outcome:
    if not _long_running(c):
        return None
    has = bool((c.security.get("container") or {}).get("livenessProbe"))
    return (not has, "livenessProbe " + ("set" if has else "missing"))


def check_readiness(c: ContainerRecord) -> Outcome:
    if not _long_running(c):
        return None
    has = bool((c.security.get("container") or {}).get("readinessProbe"))
    return (not has, "readinessProbe " + ("set" if has else "missing"))


def check_seccomp(c: ContainerRecord) -> Outcome:
    ctype = (_sc(c).get("seccompProfile") or {}).get("type")
    ptype = (_psc(c).get("seccompProfile") or {}).get("type")
    eff = ctype or ptype
    if eff is None:
        return True, "seccompProfile unset at pod and container level"
    return (eff == "Unconfined", f"seccompProfile: {eff}")


def check_host_namespaces(c: ContainerRecord, inv: InventorySnapshot | None = None) -> Outcome:
    pod = c.security.get("pod") or {}
    on = [k for k in ("hostPID", "hostIPC", "hostNetwork") if pod.get(k) is True]
    return (bool(on), ", ".join(f"{k}: true" for k in on) if on else "host namespaces not shared")


def check_host_path(c: ContainerRecord, inv: InventorySnapshot | None = None) -> Outcome:
    vols = (c.security.get("pod") or {}).get("hostPathVolumes") or []
    return (bool(vols), "hostPath volumes: " + ", ".join(vols) if vols else "no hostPath volumes")


def check_automount(c: ContainerRecord, inv: InventorySnapshot | None = None) -> Outcome:
    pod = c.security.get("pod") or {}
    sa = pod.get("serviceAccountName") or "default"
    automount = pod.get("automountServiceAccountToken")
    failed = automount is not False and sa == "default"
    return (failed, f"serviceAccount: {sa}, automountServiceAccountToken: "
            f"{'unset' if automount is None else str(automount).lower()}")


def check_netpol(c: ContainerRecord, inv: InventorySnapshot | None = None) -> Outcome:
    if inv is None or inv.network_policies is None:
        return None
    for np in inv.network_policies:
        if np.namespace == c.namespace and selector_matches(np.pod_selector, c.pod_labels):
            return False, f"selected by NetworkPolicy {np.name}"
    return True, "no NetworkPolicy selects this pod"


CONTAINER_CHECKS: dict[str, Callable[[ContainerRecord], Outcome]] = {
    "privileged": check_privileged,
    "run-as-root": check_run_as_root,
    "privilege-escalation": linux_only(check_privilege_escalation),
    "added-capabilities": linux_only(check_added_capabilities),
    "capabilities-not-dropped": linux_only(check_caps_dropped),
    "writable-rootfs": linux_only(check_writable_rootfs),
    "no-resource-limits": check_limits,
    "no-resource-requests": check_requests,
    "mutable-tag": check_mutable_tag,
    "no-liveness-probe": check_liveness,
    "no-readiness-probe": check_readiness,
    "seccomp-unconfined": linux_only(check_seccomp),
}
POD_CHECKS: dict[str, Callable[[ContainerRecord, InventorySnapshot | None], Outcome]] = {
    "host-namespaces": check_host_namespaces,
    "host-path": check_host_path,
    "automount-sa-token": check_automount,
    "no-netpol": check_netpol,
}


def workload_key(c: ContainerRecord) -> tuple[str, str, str]:
    return (c.namespace, c.workload_kind, c.workload_name)


def representative_pod(containers: list[ContainerRecord]) -> list[ContainerRecord]:
    """Pods of one workload share a template: evaluate one (prefer a running pod)."""
    pods: dict[str, list[ContainerRecord]] = {}
    for c in containers:
        pods.setdefault(c.pod, []).append(c)
    best = sorted(pods.items(), key=lambda kv: (not any(x.running for x in kv[1]), kv[0]))
    return best[0][1] if best else []


def _result(check: CheckDef, c: ContainerRecord, container: str, outcome: Outcome) -> CheckResult | None:
    if outcome is None:
        return None
    failed, detail = outcome[0], outcome[1]
    sev = outcome[2] if len(outcome) > 2 else check.severity  # type: ignore[misc]
    system = c.namespace in SYSTEM_NAMESPACES
    return CheckResult(
        check_id=check.id, namespace=c.namespace, kind=c.workload_kind, name=c.workload_name,
        container=container, status="fail" if failed else "pass", detail=detail, severity=sev,
        weight=check_weight(sev, c.namespace) if failed else 0.0, system_namespace=system, pod=c.pod,
    )


def evaluate_workload(containers: list[ContainerRecord], inv: InventorySnapshot | None = None) -> list[CheckResult]:
    pod = [c for c in representative_pod(containers) if c.container_type != "ephemeral"]
    if not pod:
        return []
    results: list[CheckResult] = []
    for c in pod:
        for check_id, fn in CONTAINER_CHECKS.items():
            r = _result(CHECKS_BY_ID[check_id], c, c.container, fn(c))
            if r:
                results.append(r)
    first = pod[0]
    for check_id, fn in POD_CHECKS.items():
        r = _result(CHECKS_BY_ID[check_id], first, "", fn(first, inv))
        if r:
            results.append(r)
    return results


@dataclass
class WorkloadPosture:
    namespace: str
    kind: str
    name: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def failed_weight(self) -> float:
        return sum(r.weight for r in self.results if r.status == "fail")

    @property
    def score(self) -> float:
        return posture_score(r.weight for r in self.results if r.status == "fail")

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "fail")

    @property
    def accepted(self) -> int:
        return sum(1 for r in self.results if r.status == ACCEPTED_RISK)


def apply_exceptions(results: list[CheckResult], exceptions: Iterable[object] | None,
                     today: date | None = None) -> list[CheckResult]:
    """Risk acceptances (controls_engine/exceptions.py): a failing result covered by an active
    exception becomes `accepted-risk` with weight 0 (no score penalty) and the acceptance in its
    detail; never `pass`. A lapsed exception leaves the result failing and says so."""
    if not exceptions:
        return results
    for r in results:
        if r.status != "fail":
            continue
        active, expired = find_exception(exceptions, r.kind, r.namespace, r.name, check=r.check_id, today=today)
        if active is not None:
            r.status, r.weight = ACCEPTED_RISK, 0.0
            r.detail = f"{r.detail}; {active.label()}"
        elif expired is not None and expired.expires_at is not None:
            r.detail = f"{r.detail}; risk acceptance expired {expired.expires_at.isoformat()} ({expired.reason})"
    return results


def evaluate_inventory(inv: InventorySnapshot, exceptions: Iterable[object] | None = None,
                       today: date | None = None) -> dict[tuple[str, str, str], WorkloadPosture]:
    groups: dict[tuple[str, str, str], list[ContainerRecord]] = {}
    for c in inv.containers:
        groups.setdefault(workload_key(c), []).append(c)
    out: dict[tuple[str, str, str], WorkloadPosture] = {}
    for key, cs in groups.items():
        out[key] = WorkloadPosture(*key, results=apply_exceptions(evaluate_workload(cs, inv), exceptions, today))
    return out
