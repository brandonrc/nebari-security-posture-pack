"""Inventory data model shared by the K8s collector, posture checks and the worker."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ContainerRecord:
    namespace: str
    pod: str
    container: str
    container_type: str  # container | init | ephemeral
    image: str
    image_id: str | None
    running: bool
    pod_phase: str
    workload_kind: str
    workload_name: str
    pack: str | None = None
    pod_uid: str | None = None
    pod_labels: dict[str, str] = field(default_factory=dict)
    # snapshot used by posture checks:
    #   container: securityContext, resources, livenessProbe, readinessProbe, restartPolicy,
    #              hostProcess (effective Windows windowsOptions.hostProcess)
    #   pod: os ("windows"/"linux"/None), hostPID/hostIPC/hostNetwork, hostPathVolumes,
    #        securityContext, automountServiceAccountToken, serviceAccountName
    security: dict[str, Any] = field(default_factory=dict)
    image_key: str | None = None  # filled by the worker (images.identify_image)


@dataclass
class NetworkPolicyInfo:
    namespace: str
    name: str
    pod_selector: dict[str, Any]


@dataclass
class NamespaceInfo:
    name: str
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def managed(self) -> bool:
        return self.labels.get("nebari.dev/managed") == "true"


@dataclass
class NebariAppInfo:
    namespace: str
    name: str
    display_name: str | None
    instance: str | None
    hostname: str | None = None

    @property
    def pack(self) -> str:
        return self.display_name or self.name


@dataclass
class InventorySnapshot:
    containers: list[ContainerRecord]
    namespaces: dict[str, NamespaceInfo] = field(default_factory=dict)
    # None => NetworkPolicies could not be listed (RBAC): the no-netpol check is skipped
    network_policies: list[NetworkPolicyInfo] | None = field(default_factory=list)
    nebari_apps: list[NebariAppInfo] = field(default_factory=list)
    collected_at: datetime | None = None
    errors: list[str] = field(default_factory=list)


def selector_matches(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    """Kubernetes LabelSelector semantics; an empty selector matches everything."""
    selector = selector or {}
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions") or []:
        key = expr.get("key")
        op = (expr.get("operator") or "").lower()
        values = expr.get("values") or []
        if op == "in" and labels.get(key) not in values:
            return False
        if op == "notin" and key in labels and labels[key] in values:
            return False
        if op == "exists" and key not in labels:
            return False
        if op == "doesnotexist" and key in labels:
            return False
    return True
