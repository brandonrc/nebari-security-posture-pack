"""Fake Kubernetes / Keycloak / HTTP clients and a fully compliant "good world"."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from posture.controls_engine.context import EngineConfig, EngineContext, K8sForbidden, K8sNotFound, KeycloakError

NOW = datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class FakeKube:
    """`paths`: path -> dict (GET object) or list (collection items). Missing path -> 404."""

    def __init__(self, paths: dict[str, Any], forbidden: set[str] | None = None, page_size: int | None = None):
        self.paths = paths
        self.forbidden = forbidden or set()
        self.page_size = page_size
        self.calls: list[str] = []

    async def get(self, path: str, query: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append(path)
        if path in self.forbidden or "*" in self.forbidden:
            raise K8sForbidden(path, 403, "forbidden")
        if path not in self.paths:
            raise K8sNotFound(path, 404, "not found")
        v = self.paths[path]
        if isinstance(v, Exception):
            raise v
        if isinstance(v, list):
            if not self.page_size:
                return {"items": copy.deepcopy(v), "metadata": {}}
            start = int((query or {}).get("continue") or 0)
            chunk = v[start:start + self.page_size]
            nxt = start + self.page_size
            return {"items": copy.deepcopy(chunk), "metadata": {"continue": str(nxt) if nxt < len(v) else ""}}
        return copy.deepcopy(v)


class FakeKeycloak:
    def __init__(self, paths: dict[str, Any], error: str | None = None):
        self.paths = paths
        self.error = error

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if self.error:
            raise KeycloakError(self.error)
        if path not in self.paths:
            raise KeycloakError(f"GET {path}: HTTP 404")
        return copy.deepcopy(self.paths[path])


class FakeHTTP:
    """`urls`: url -> (status, body) | Exception. body: dict/list -> JSON, str -> text."""

    def __init__(self, urls: dict[str, Any]):
        self.urls = urls

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        v = self.urls.get(url)
        req = httpx.Request("GET", url)
        if v is None:
            raise httpx.ConnectError("connection refused", request=req)
        if isinstance(v, Exception):
            raise v
        status, body = v[0], v[1]
        headers = v[2] if len(v) > 2 else {}
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body, headers=headers, request=req)
        return httpx.Response(status, text=body, headers=headers, request=req)

    async def aclose(self) -> None:
        pass


LOKI = "http://loki.monitoring.svc.cluster.local:3100"
PROM = "http://prometheus.monitoring.svc.cluster.local:9090"
AM = "http://alertmanager.monitoring.svc.cluster.local:9093"
REG = "http://registry.container-registry.svc.cluster.local:5000"


def ns(name: str, enforce: str | None = None) -> dict:
    labels = {"kubernetes.io/metadata.name": name}
    if enforce:
        labels["pod-security.kubernetes.io/enforce"] = enforce
    return {"metadata": {"name": name, "labels": labels}, "status": {"phase": "Active"}}


def svc(namespace: str, name: str, port: int, stype: str = "ClusterIP", cluster_ip: str = "10.0.0.10",
        node_port: int | None = None) -> dict:
    p = {"port": port}
    if node_port:
        p["nodePort"] = node_port
    return {"metadata": {"namespace": namespace, "name": name},
            "spec": {"type": stype, "clusterIP": cluster_ip, "ports": [p]}}


def good_world() -> dict[str, Any]:
    k8s = {
        "/api/v1/namespaces": [ns("kube-system"), ns("apps", "restricted"), ns("monitoring", "baseline")],
        "/api/v1/pods": [
            {"metadata": {"namespace": "apps", "name": "web-1"}, "status": {"phase": "Running"}},
            {"metadata": {"namespace": "monitoring", "name": "loki-0"}, "status": {"phase": "Running"}},
            {"metadata": {"namespace": "kube-system", "name": "kube-apiserver-node1",
                          "labels": {"component": "kube-apiserver"}},
             "spec": {"containers": [{"command": ["kube-apiserver", "--audit-policy-file=/etc/audit.yaml",
                                                  "--audit-log-path=/var/log/audit.log"]}]},
             "status": {"phase": "Running"}},
        ],
        "/api/v1/services": [svc("monitoring", "loki", 3100), svc("monitoring", "prometheus", 9090),
                             svc("monitoring", "alertmanager", 9093),
                             svc("container-registry", "registry", 5000, cluster_ip="10.0.0.49")],
        "/api/v1/serviceaccounts": [
            {"metadata": {"namespace": "apps", "name": "default"}, "automountServiceAccountToken": False},
            {"metadata": {"namespace": "monitoring", "name": "default"}, "automountServiceAccountToken": False},
            {"metadata": {"namespace": "kube-system", "name": "default"}}],
        "/api/v1/nodes": [{"metadata": {"name": "node1"}, "status": {"nodeInfo": {"kubeletVersion": "v1.35.6"}}}],
        "/version": {"gitVersion": "v1.35.6"},
        "/apis/networking.k8s.io/v1/networkpolicies": [
            {"metadata": {"namespace": "apps", "name": "default-deny"},
             "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
            {"metadata": {"namespace": "monitoring", "name": "deny"}, "spec": {"podSelector": {}}},
            {"metadata": {"namespace": "monitoring", "name": "deny-egress"},
             "spec": {"podSelector": {}, "policyTypes": ["Egress"]}}],
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": [
            {"metadata": {"name": "cluster-admin"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "Group", "name": "system:masters"}]},
            {"metadata": {"name": "ops-admin"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "User", "name": "alice"}]},
            {"metadata": {"name": "system:public-info-viewer"},
             "roleRef": {"kind": "ClusterRole", "name": "system:public-info-viewer"},
             "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]}],
        "/apis/rbac.authorization.k8s.io/v1/rolebindings": [],
        "/apis/gateway.networking.k8s.io/v1/gateways": [{
            "metadata": {"namespace": "envoy-gateway-system", "name": "nebari-gateway"},
            "spec": {"listeners": [
                {"name": "http", "port": 80, "protocol": "HTTP"},
                {"name": "https", "port": 443, "protocol": "HTTPS",
                 "tls": {"mode": "Terminate", "certificateRefs": [{"name": "gw-tls"}]}}]},
            "status": {"addresses": [{"value": "10.0.0.200"}], "listeners": [
                {"name": "https", "conditions": [{"type": "Programmed", "status": "True"}]},
                {"name": "http", "conditions": [{"type": "Programmed", "status": "True"}]}]}}],
        "/apis/gateway.networking.k8s.io/v1/httproutes": [
            {"metadata": {"namespace": "apps", "name": "web-route",
                          "ownerReferences": [{"kind": "NebariApp", "name": "web"}]},
             "spec": {"parentRefs": [{"name": "nebari-gateway", "namespace": "envoy-gateway-system",
                                      "sectionName": "https"}],
                      "rules": [{"backendRefs": [{"name": "web", "port": 80}]}]}},
            {"metadata": {"namespace": "envoy-gateway-system", "name": "https-redirect"},
             "spec": {"parentRefs": [{"name": "nebari-gateway", "sectionName": "http"}],
                      "rules": [{"filters": [{"type": "RequestRedirect",
                                              "requestRedirect": {"scheme": "https", "statusCode": 301}}]}]}}],
        "/apis/gateway.envoyproxy.io/v1alpha1/securitypolicies": [
            {"metadata": {"namespace": "apps", "name": "web-security"},
             "spec": {"oidc": {"clientID": "web"}, "targetRefs": [{"kind": "HTTPRoute", "name": "web-route"}]}}],
        "/apis/gateway.envoyproxy.io/v1alpha1/clienttrafficpolicies": [
            {"metadata": {"namespace": "envoy-gateway-system", "name": "tls"},
             "spec": {"targetRefs": [{"kind": "Gateway", "name": "nebari-gateway"}], "tls": {"minVersion": "1.2"}}}],
        "/apis/reconcilers.nebari.dev/v1/nebariapps": [
            {"metadata": {"namespace": "apps", "name": "web"},
             "spec": {"auth": {"enabled": True, "groups": ["admin"]}, "landingPage": {"enabled": True}},
             "status": {"serviceDiscovery": {"visibility": "private", "requiredGroups": ["admin"]}}}],
        "/apis/cert-manager.io/v1/clusterissuers": [
            {"metadata": {"name": "org-ca"}, "spec": {"ca": {"secretName": "ca"}},
             "status": {"conditions": [{"type": "Ready", "status": "True"}]}}],
        "/apis/cert-manager.io/v1/certificates": [
            {"metadata": {"namespace": "envoy-gateway-system", "name": "gw"}, "spec": {"issuerRef": {"name": "org-ca"}},
             "status": {"conditions": [{"type": "Ready", "status": "True"}],
                        "notAfter": iso(NOW + timedelta(days=60)), "renewalTime": iso(NOW + timedelta(days=30))}}],
    }
    keycloak = {
        "": {"bruteForceProtected": True, "failureFactor": 3, "passwordPolicy": "length(12) and digits(1)",
             "ssoSessionIdleTimeout": 900, "ssoSessionMaxLifespan": 36000, "rememberMe": False,
             "registrationAllowed": False, "sslRequired": "external"},
        "/events/config": {"eventsEnabled": True, "eventsExpiration": 7776000, "adminEventsEnabled": True,
                           "adminEventsDetailsEnabled": True,
                           "enabledEventTypes": ["LOGIN", "LOGIN_ERROR", "LOGOUT", "CODE_TO_TOKEN"]},
        "/groups": [{"id": "g1", "name": "admin"}],
        "/groups/g1/members": [{"id": "u1", "username": "alice", "enabled": True}],
        "/users/u1/credentials": [{"type": "password"}, {"type": "otp"}],
        "/roles": [{"name": "admin"}, {"name": "user"}],
        "/roles/admin/users": [{"username": "alice"}],
        "/roles/admin/groups": [],
    }
    http = {
        f"{LOKI}/loki/api/v1/label/namespace/values": (200, {"status": "success",
                                                             "data": ["apps", "monitoring", "kube-system"]}),
        f"{LOKI}/config": (200, "limits_config:\n  retention_period: 2160h\ncompactor:\n  retention_enabled: true\n"),
        f"{PROM}/api/v1/targets": (200, {"data": {"activeTargets": [
            {"labels": {"job": "kubelet"}, "health": "up"}, {"labels": {"job": "node"}, "health": "up"}]}}),
        f"{PROM}/api/v1/rules": (200, {"data": {"groups": [
            {"name": "loki", "rules": [{"type": "alerting", "name": "LokiRequestErrors", "labels": {"severity": "critical"}},
                                       {"type": "alerting", "name": "PromtailRequestsErrors"}]},
            {"name": "security", "rules": [{"type": "alerting", "name": "KeycloakBruteForceLockouts",
                                            "labels": {"category": "security"}}]},
            {"name": "node", "rules": [{"type": "alerting", "name": "NodeFilesystemAlmostFull"}]}]}}),
        f"{AM}/api/v2/status": (200, {"config": {"original": "route:\n  receiver: ops\nreceivers:\n- name: ops\n"
                                                             "  email_configs:\n  - to: ops@example.org\n"}}),
        f"{REG}/v2/": (401, {"errors": []}, {"www-authenticate": 'Basic realm="registry"'}),
    }
    snapshot = {
        "scanIntervalHours": 6,
        "slaDays": {"critical": 15, "high": 30, "medium": 90, "low": 180},
        "scanners": [{"name": n, "enabled": True, "dbUpdatedAt": NOW - timedelta(hours=5), "healthy": True}
                     for n in ("trivy", "grype", "clair")],
        "lastDoneScan": {"id": 7, "finishedAt": NOW - timedelta(hours=1), "inventoryComplete": True,
                         "imagesTotal": 12, "score": 88.0},
        "openFindings": 3,
        "slaOverdue": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "postureFailures": [{"checkId": "privileged", "namespace": "kube-system", "kind": "DaemonSet",
                             "name": "calico", "severity": "critical"}],
        "inventory": {"containers": 30, "images": 12},
        "latestPoam": {"id": "r1", "scanId": 7, "createdAt": iso(NOW)},
    }
    return {"k8s": k8s, "keycloak": keycloak, "http": http, "snapshot": snapshot,
            "config": {"admin_subjects": ["alice", "User:alice"], "registry_url": REG.split("://")[1],
                       "tls_probe": False}}


def make_ctx(world: dict[str, Any], *, k8s: bool = True, keycloak: bool = True, forbidden: set[str] | None = None,
             keycloak_error: str | None = None) -> EngineContext:
    cfg = EngineConfig(**world.get("config", {}))
    return EngineContext(
        config=cfg,
        k8s=FakeKube(world["k8s"], forbidden=forbidden) if k8s else None,
        keycloak=FakeKeycloak(world["keycloak"], error=keycloak_error) if keycloak else None,
        http=FakeHTTP(world["http"]),
        snapshot=world["snapshot"],
        keycloak_error=None if keycloak else "Keycloak admin secret unreadable",
    )
