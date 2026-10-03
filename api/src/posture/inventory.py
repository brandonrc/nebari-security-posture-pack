"""Cluster inventory via the Kubernetes API (DESIGN §4.1).

Uses the official (sync) client in a worker thread. Read-only: pods, namespaces,
replicasets, jobs, networkpolicies and nebariapps.reconcilers.nebari.dev.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from .inventory_model import (
    ContainerRecord,
    InventorySnapshot,
    NamespaceInfo,
    NebariAppInfo,
    NetworkPolicyInfo,
)
from .logs import get_logger

log = get_logger(__name__)

INSTANCE_LABELS = ("app.kubernetes.io/instance", "release", "app.kubernetes.io/part-of")


def _load_kube_config() -> None:
    from kubernetes import config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def _sanitize(client_obj: Any) -> Any:
    from kubernetes.client import ApiClient

    return ApiClient().sanitize_for_serialization(client_obj)


def _list_all(fn, **kw) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cont = None
    while True:
        resp = fn(limit=500, _continue=cont, **kw) if cont else fn(limit=500, **kw)
        data = resp if isinstance(resp, dict) else _sanitize(resp)
        items.extend(data.get("items") or [])
        cont = (data.get("metadata") or {}).get("continue")
        if not cont:
            return items


def resolve_owner(pod: dict[str, Any], replicasets: dict[tuple[str, str], dict], jobs: dict[tuple[str, str], dict]) -> tuple[str, str]:
    """Pod -> ReplicaSet -> Deployment, Pod -> Job -> CronJob, else first controller owner."""
    meta = pod.get("metadata") or {}
    ns = meta.get("namespace") or ""
    owners = meta.get("ownerReferences") or []
    owner = next((o for o in owners if o.get("controller")), owners[0] if owners else None)
    if not owner:
        return "Pod", meta.get("name") or ""
    kind, name = owner.get("kind") or "Pod", owner.get("name") or ""
    lookup = {"ReplicaSet": replicasets, "Job": jobs}.get(kind)
    if lookup is not None:
        parent = lookup.get((ns, name))
        if parent:
            pown = (parent.get("metadata") or {}).get("ownerReferences") or []
            po = next((o for o in pown if o.get("controller")), pown[0] if pown else None)
            if po:
                return po.get("kind") or kind, po.get("name") or name
        elif kind == "ReplicaSet":
            # RS not visible: strip pod-template-hash suffix heuristically
            hash_ = ((meta.get("labels") or {}).get("pod-template-hash"))
            if hash_ and name.endswith("-" + hash_):
                return "Deployment", name[: -len(hash_) - 1]
    return kind, name


def map_pack(ns: str, labels: dict[str, str], apps: list[NebariAppInfo]) -> str | None:
    in_ns = [a for a in apps if a.namespace == ns]
    if not in_ns:
        return None
    candidates = [labels.get(k) for k in INSTANCE_LABELS if labels.get(k)]
    for inst in candidates:
        matches = [a for a in in_ns if a.instance == inst]
        if matches:
            return sorted(matches, key=lambda a: (a.display_name is None, a.name))[0].pack
    return sorted(in_ns, key=lambda a: (a.display_name is None, a.name))[0].pack


def pod_os(pod_spec: dict[str, Any]) -> str | None:
    """`spec.os.name` (K8s 1.25+), else the `kubernetes.io/os` nodeSelector; None = unknown (Linux)."""
    name = ((pod_spec.get("os") or {}).get("name")) or (pod_spec.get("nodeSelector") or {}).get("kubernetes.io/os")
    return str(name).lower() if name else None


def host_process(pod_spec: dict[str, Any], c: dict[str, Any]) -> bool:
    """Effective `windowsOptions.hostProcess` (container overrides pod): the Windows equivalent of
    privileged, the container runs directly on the node as a host process."""
    cv = ((c.get("securityContext") or {}).get("windowsOptions") or {}).get("hostProcess")
    if cv is not None:
        return cv is True
    return (((pod_spec.get("securityContext") or {}).get("windowsOptions") or {}).get("hostProcess")) is True


def _security_snapshot(pod_spec: dict[str, Any], c: dict[str, Any]) -> dict[str, Any]:
    return {
        "container": {
            "securityContext": c.get("securityContext") or {},
            "resources": c.get("resources") or {},
            "livenessProbe": bool(c.get("livenessProbe")),
            "readinessProbe": bool(c.get("readinessProbe")),
            "restartPolicy": c.get("restartPolicy"),
            "hostProcess": host_process(pod_spec, c),
        },
        "pod": {
            "os": pod_os(pod_spec),
            "hostPID": bool(pod_spec.get("hostPID")),
            "hostIPC": bool(pod_spec.get("hostIPC")),
            "hostNetwork": bool(pod_spec.get("hostNetwork")),
            "hostPathVolumes": [v.get("name") for v in pod_spec.get("volumes") or [] if v.get("hostPath")],
            "securityContext": pod_spec.get("securityContext") or {},
            "automountServiceAccountToken": pod_spec.get("automountServiceAccountToken"),
            "serviceAccountName": pod_spec.get("serviceAccountName") or "default",
        },
    }


def build_containers(pods: list[dict[str, Any]], replicasets: dict, jobs: dict, apps: list[NebariAppInfo],
                     excluded: set[str]) -> list[ContainerRecord]:
    out: list[ContainerRecord] = []
    for pod in pods:
        meta = pod.get("metadata") or {}
        ns = meta.get("namespace") or ""
        if ns in excluded:
            continue
        spec = pod.get("spec") or {}
        status = pod.get("status") or {}
        phase = status.get("phase") or "Unknown"
        labels = meta.get("labels") or {}
        kind, wname = resolve_owner(pod, replicasets, jobs)
        pack = map_pack(ns, labels, apps)
        statuses: dict[tuple[str, str], dict] = {}
        for typ, key in (("container", "containerStatuses"), ("init", "initContainerStatuses"),
                         ("ephemeral", "ephemeralContainerStatuses")):
            for cs in status.get(key) or []:
                statuses[(typ, cs.get("name"))] = cs
        for typ, key in (("container", "containers"), ("init", "initContainers"),
                         ("ephemeral", "ephemeralContainers")):
            for c in spec.get(key) or []:
                cs = statuses.get((typ, c.get("name"))) or {}
                out.append(ContainerRecord(
                    namespace=ns,
                    pod=meta.get("name") or "",
                    pod_uid=meta.get("uid"),
                    container=c.get("name") or "",
                    container_type=typ,
                    image=c.get("image") or cs.get("image") or "",
                    image_id=cs.get("imageID") or None,
                    running=phase == "Running",
                    pod_phase=phase,
                    workload_kind=kind,
                    workload_name=wname,
                    pack=pack,
                    pod_labels=dict(labels),
                    security=_security_snapshot(spec, c),
                ))
    return out


def parse_nebariapps(items: list[dict[str, Any]]) -> list[NebariAppInfo]:
    apps = []
    for a in items:
        meta = a.get("metadata") or {}
        spec = a.get("spec") or {}
        apps.append(NebariAppInfo(
            namespace=meta.get("namespace") or "",
            name=meta.get("name") or "",
            display_name=((spec.get("landingPage") or {}).get("displayName")) or None,
            instance=(meta.get("labels") or {}).get("app.kubernetes.io/instance"),
            hostname=spec.get("hostname"),
        ))
    return apps


def collect_sync(excluded_namespaces: list[str] | None = None) -> InventorySnapshot:
    from kubernetes import client
    from kubernetes.client.exceptions import ApiException

    _load_kube_config()
    core = client.CoreV1Api()
    apps_api = client.AppsV1Api()
    batch = client.BatchV1Api()
    net = client.NetworkingV1Api()
    custom = client.CustomObjectsApi()
    errors: list[str] = []
    excluded = set(excluded_namespaces or [])

    pods = _list_all(core.list_pod_for_all_namespaces)
    namespaces = {}
    try:
        for n in _list_all(core.list_namespace):
            m = n.get("metadata") or {}
            namespaces[m.get("name")] = NamespaceInfo(m.get("name"), dict(m.get("labels") or {}))
    except ApiException as e:
        errors.append(f"namespaces: {e.status} {e.reason}")

    def _index(fn, label):
        try:
            return {((i.get("metadata") or {}).get("namespace"), (i.get("metadata") or {}).get("name")): i
                    for i in _list_all(fn)}
        except ApiException as e:
            errors.append(f"{label}: {e.status} {e.reason}")
            return {}

    replicasets = _index(apps_api.list_replica_set_for_all_namespaces, "replicasets")
    jobs = _index(batch.list_job_for_all_namespaces, "jobs")

    netpols: list[NetworkPolicyInfo] | None
    try:
        netpols = [
            NetworkPolicyInfo((p.get("metadata") or {}).get("namespace"), (p.get("metadata") or {}).get("name"),
                              ((p.get("spec") or {}).get("podSelector")) or {})
            for p in _list_all(net.list_network_policy_for_all_namespaces)
        ]
    except ApiException as e:
        errors.append(f"networkpolicies: {e.status} {e.reason} (no-netpol check skipped)")
        netpols = None

    try:
        raw_apps = custom.list_cluster_custom_object("reconcilers.nebari.dev", "v1", "nebariapps").get("items") or []
    except ApiException as e:
        if e.status != 404:
            errors.append(f"nebariapps: {e.status} {e.reason}")
        raw_apps = []
    apps = parse_nebariapps(raw_apps)

    containers = build_containers(pods, replicasets, jobs, apps, excluded)
    for name in list(namespaces):
        if name in excluded:
            namespaces.pop(name)
    return InventorySnapshot(
        containers=containers,
        namespaces=namespaces,
        network_policies=netpols,
        nebari_apps=apps,
        collected_at=datetime.now(UTC),
        errors=errors,
    )


async def collect(excluded_namespaces: list[str] | None = None) -> InventorySnapshot:
    snap = await asyncio.to_thread(collect_sync, excluded_namespaces)
    log.info("inventory.collected", containers=len(snap.containers), namespaces=len(snap.namespaces),
             nebariapps=len(snap.nebari_apps), errors=len(snap.errors))
    for err in snap.errors:
        log.warning("inventory.partial", error=err)
    return snap
