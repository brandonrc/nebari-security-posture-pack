"""Every assertion: pass (good world), fail (one targeted mutation) and unknown (missing evidence)."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from posture.controls_engine.assertions import all_assertions, get_assertion
from posture.controls_engine.engine import run_one

from .fakes import AM, LOKI, NOW, PROM, REG, good_world, iso, make_ctx, ns, svc

IDS = [a.id for a in all_assertions()]


def k(w, path):
    return w["k8s"][path]


def _set(d, key, value):
    d[key] = value


FAIL = {
    # keycloak
    "kc-brute-force-protection": lambda w: w["keycloak"][""].update(failureFactor=30),
    "kc-password-policy": lambda w: w["keycloak"][""].update(passwordPolicy=None),
    "kc-admin-mfa": lambda w: _set(w["keycloak"], "/users/u1/credentials", [{"type": "password"}]),
    "kc-session-timeouts": lambda w: w["keycloak"][""].update(ssoSessionIdleTimeout=1800),
    "kc-remember-me-disabled": lambda w: w["keycloak"][""].update(rememberMe=True),
    "kc-self-registration-disabled": lambda w: w["keycloak"][""].update(registrationAllowed=True),
    "kc-login-events": lambda w: w["keycloak"]["/events/config"].update(eventsEnabled=False),
    "kc-admin-events": lambda w: w["keycloak"]["/events/config"].update(adminEventsDetailsEnabled=False),
    "kc-admin-role-allowlist": lambda w: _set(w["keycloak"], "/roles/admin/users",
                                              [{"username": "alice"}, {"username": "mallory"}]),
    "kc-ssl-required": lambda w: w["keycloak"][""].update(sslRequired="none"),
    # gateway / operator
    "gw-https-listener": lambda w: k(w, "/apis/gateway.networking.k8s.io/v1/gateways")[0]["spec"]["listeners"].pop(),
    "gw-http-redirect": lambda w: k(w, "/apis/gateway.networking.k8s.io/v1/httproutes").append(
        {"metadata": {"namespace": "keycloak", "name": "kc"},
         "spec": {"parentRefs": [{"name": "nebari-gateway", "namespace": "envoy-gateway-system"}],
                  "rules": [{"backendRefs": [{"name": "keycloak"}]}]}}),
    "gw-tls-min-version": lambda w: k(w, "/apis/gateway.envoyproxy.io/v1alpha1/clienttrafficpolicies")[0]["spec"][
        "tls"].update(minVersion="1.1"),
    "app-gateway-auth": lambda w: _set(w["k8s"], "/apis/gateway.envoyproxy.io/v1alpha1/securitypolicies", []),
    "app-landing-visibility": lambda w: k(w, "/apis/reconcilers.nebari.dev/v1/nebariapps")[0]["status"][
        "serviceDiscovery"].update(visibility="public"),
    # cert-manager
    "cm-issuer-ready": lambda w: k(w, "/apis/cert-manager.io/v1/clusterissuers")[0]["status"].update(
        conditions=[{"type": "Ready", "status": "False"}]),
    "cm-certificates-valid": lambda w: k(w, "/apis/cert-manager.io/v1/certificates")[0]["status"].update(
        notAfter=iso(NOW + timedelta(days=3))),
    # kubernetes
    "k8s-pod-security-admission": lambda w: k(w, "/api/v1/namespaces").append(ns("legacy")),
    "k8s-default-deny-ingress": lambda w: _set(w["k8s"], "/apis/networking.k8s.io/v1/networkpolicies", []),
    "k8s-cluster-admin-bindings": lambda w: w["config"].update(admin_subjects=[]),
    "k8s-default-sa-automount": lambda w: k(w, "/api/v1/serviceaccounts")[0].pop("automountServiceAccountToken"),
    "k8s-no-anonymous-access": lambda w: k(w, "/apis/rbac.authorization.k8s.io/v1/rolebindings").append(
        {"metadata": {"namespace": "apps", "name": "open"}, "roleRef": {"kind": "Role", "name": "edit"},
         "subjects": [{"kind": "User", "name": "system:anonymous"}]}),
    "k8s-supported-version": lambda w: k(w, "/api/v1/nodes")[0]["status"]["nodeInfo"].update(
        kubeletVersion="v1.29.4"),
    "k8s-api-audit-logging": lambda w: k(w, "/api/v1/pods")[2]["spec"]["containers"][0].update(
        command=["kube-apiserver"]),
    "k8s-workload-least-privilege": lambda w: w["snapshot"]["postureFailures"].append(
        {"checkId": "privileged", "namespace": "apps", "kind": "Deployment", "name": "web", "severity": "critical"}),
    # observability
    "log-ingest-all-namespaces": lambda w: _set(w["http"], f"{LOKI}/loki/api/v1/label/namespace/values",
                                                (200, {"data": ["apps"]})),
    "log-retention": lambda w: _set(w["http"], f"{LOKI}/config", (200, "limits_config:\n  retention_period: 744h\n"
                                                                       "compactor:\n  retention_enabled: true\n")),
    "mon-prometheus-scraping": lambda w: _set(w["http"], f"{PROM}/api/v1/targets", (200, {"data": {
        "activeTargets": [{"labels": {"job": "kubelet"}, "health": "down"}]}})),
    "mon-alert-receivers": lambda w: _set(w["http"], f"{AM}/api/v2/status",
                                          (200, {"config": {"original": "receivers:\n- name: 'null'\n"}})),
    # registry
    "reg-access-restricted": lambda w: (_set(w["http"], f"{REG}/v2/", (200, {})),
                                        _set(w["k8s"], "/api/v1/services", [svc(
                                            "container-registry", "registry", 5000, "NodePort", node_port=32000)])),
    # pack
    "pack-scan-recent": lambda w: w["snapshot"]["lastDoneScan"].update(finishedAt=NOW - timedelta(hours=20)),
    "pack-scanner-db-fresh": lambda w: w["snapshot"]["scanners"][1].update(dbUpdatedAt=NOW - timedelta(days=5)),
    "pack-poam-current": lambda w: w["snapshot"]["latestPoam"].update(scanId=6),
    "pack-sla-overdue": lambda w: w["snapshot"]["slaOverdue"].update(high=2),
    "pack-inventory-current": lambda w: w["snapshot"]["lastDoneScan"].update(inventoryComplete=False),
}

# A world where the evidence source is missing / unreachable -> unknown.
UNKNOWN = {
    **{i: {"keycloak": False} for i in IDS if i.startswith("kc-")},
    **{i: {"forbidden": {"*"}} for i in IDS if i.startswith(("gw-", "app-", "cm-", "k8s-"))},
    "k8s-api-audit-logging": {"mutate": lambda w: k(w, "/api/v1/pods").pop(2)},  # API server not visible
    "k8s-workload-least-privilege": {"mutate": lambda w: w["snapshot"].pop("lastDoneScan")},
    "log-ingest-all-namespaces": {"mutate": lambda w: w["http"].pop(f"{LOKI}/loki/api/v1/label/namespace/values")},
    "log-retention": {"mutate": lambda w: w["http"].pop(f"{LOKI}/config")},
    "mon-prometheus-scraping": {"mutate": lambda w: w["http"].pop(f"{PROM}/api/v1/targets")},
    "mon-alert-receivers": {"mutate": lambda w: w["http"].pop(f"{AM}/api/v2/status")},
    "reg-access-restricted": {"mutate": lambda w: w["http"].pop(f"{REG}/v2/")},
    "pack-scan-recent": {"mutate": lambda w: _set(w, "snapshot", None)},  # evaluation error -> unknown
    "pack-inventory-current": {"mutate": lambda w: _set(w, "snapshot", {"lastDoneScan": 5})},
    "pack-scanner-db-fresh": {"mutate": lambda w: w["snapshot"].update(scanners=[])},
    "pack-poam-current": {"mutate": lambda w: w["snapshot"].pop("lastDoneScan")},
    "pack-sla-overdue": {"mutate": lambda w: w["snapshot"].pop("lastDoneScan")},
}


def test_registry_has_at_least_25_assertions():
    assert len(IDS) >= 25 and len(set(IDS)) == len(IDS)
    for a in all_assertions():
        assert a.title and a.controls and a.component and a.severity in ("critical", "high", "medium", "low")
        assert a.description, a.id


def test_every_assertion_has_scenarios():
    assert set(FAIL) == set(IDS)
    assert set(UNKNOWN) == set(IDS)


@pytest.mark.parametrize("aid", IDS)
async def test_pass(aid):
    out = await run_one(get_assertion(aid), make_ctx(good_world()), 5)
    assert out.status == "pass", (out.detail, out.evidence)
    assert out.detail


@pytest.mark.parametrize("aid", IDS)
async def test_fail(aid):
    w = good_world()
    FAIL[aid](w)
    out = await run_one(get_assertion(aid), make_ctx(w), 5)
    assert out.status == "fail", (out.detail, out.evidence)
    assert out.detail


@pytest.mark.parametrize("aid", IDS)
async def test_unknown(aid):
    w = good_world()
    spec = UNKNOWN[aid]
    if "mutate" in spec:
        spec["mutate"](w)
    if w.get("snapshot") is None:
        w["snapshot"] = None
    ctx = make_ctx(w, keycloak=spec.get("keycloak", True), forbidden=spec.get("forbidden"))
    if w.get("snapshot") is None:
        ctx.snapshot = None  # type: ignore[assignment]
    out = await run_one(get_assertion(aid), ctx, 5)
    assert out.status == "unknown", (out.detail, out.evidence)


# ---------------------------------------------------------------- specific behaviours
async def test_no_kubernetes_client_is_unknown():
    out = await run_one(get_assertion("k8s-pod-security-admission"), make_ctx(good_world(), k8s=False), 5)
    assert out.status == "unknown" and "Kubernetes" in out.detail


async def test_forbidden_mentions_rbac():
    out = await run_one(get_assertion("cm-issuer-ready"), make_ctx(good_world(), forbidden={"*"}), 5)
    assert out.status == "unknown" and "not permitted" in out.detail


async def test_not_installed_crds():
    w = good_world()
    for p in ("/apis/gateway.networking.k8s.io/v1/gateways", "/apis/reconcilers.nebari.dev/v1/nebariapps"):
        w["k8s"].pop(p)
    for aid in ("gw-https-listener", "gw-http-redirect", "gw-tls-min-version", "app-gateway-auth",
                "app-landing-visibility"):
        assert (await run_one(get_assertion(aid), make_ctx(w), 5)).status == "not-applicable", aid
    w["k8s"].pop("/apis/cert-manager.io/v1/clusterissuers")
    assert (await run_one(get_assertion("cm-issuer-ready"), make_ctx(w), 5)).status == "fail"


async def test_in_app_auth_annotation_documents_exception():
    w = good_world()
    app = w["k8s"]["/apis/reconcilers.nebari.dev/v1/nebariapps"][0]
    app["spec"]["auth"]["enforceAtGateway"] = False
    out = await run_one(get_assertion("app-gateway-auth"), make_ctx(w), 5)
    assert out.status == "fail" and "enforceAtGateway=false" in str(out.evidence)
    app["metadata"]["annotations"] = {"posture.nebari.dev/in-app-auth": "JupyterHub authenticates via OAuth"}
    out = await run_one(get_assertion("app-gateway-auth"), make_ctx(w), 5)
    assert out.status == "pass" and out.evidence["documentedInApp"]


async def test_admin_role_via_group_and_allowlist_forms():
    w = good_world()
    w["keycloak"]["/roles/admin/groups"] = [{"id": "g2", "name": "ops"}]
    w["keycloak"]["/groups/g2/members"] = [{"username": "bob"}]
    out = await run_one(get_assertion("kc-admin-role-allowlist"), make_ctx(w), 5)
    assert out.status == "fail" and out.evidence["notAllowlisted"] == ["bob"]
    w["config"]["admin_subjects"] = ["alice", "keycloak:bob"]
    assert (await run_one(get_assertion("kc-admin-role-allowlist"), make_ctx(w), 5)).status == "pass"


async def test_cluster_admin_serviceaccount_allowlist():
    w = good_world()
    w["k8s"]["/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"].append(
        {"metadata": {"name": "argocd"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
         "subjects": [{"kind": "ServiceAccount", "namespace": "argocd", "name": "argocd-application-controller"}]})
    assert (await run_one(get_assertion("k8s-cluster-admin-bindings"), make_ctx(w), 5)).status == "fail"
    w["config"]["admin_subjects"].append("ServiceAccount:argocd/argocd-application-controller")
    assert (await run_one(get_assertion("k8s-cluster-admin-bindings"), make_ctx(w), 5)).status == "pass"


async def test_tls_default_without_policy_uses_probe(monkeypatch):
    from posture.controls_engine.assertions import gateway

    w = good_world()
    w["k8s"]["/apis/gateway.envoyproxy.io/v1alpha1/clienttrafficpolicies"] = []
    w["config"]["tls_probe"] = True
    calls = []

    async def probe(host, port, max_version, timeout=5):
        calls.append(max_version)
        return {"handshake": "rejected"} if max_version else {"handshake": "ok", "version": "TLSv1.3"}

    monkeypatch.setattr(gateway, "_tls_probe", probe)
    out = await run_one(get_assertion("gw-tls-min-version"), make_ctx(w), 5)
    assert out.status == "pass" and len(calls) == 2
    assert out.evidence["gateways"][0]["probe"]["default"]["version"] == "TLSv1.3"

    async def accepts_old(host, port, max_version, timeout=5):
        return {"handshake": "ok", "version": "TLSv1.1"}

    monkeypatch.setattr(gateway, "_tls_probe", accepts_old)
    assert (await run_one(get_assertion("gw-tls-min-version"), make_ctx(w), 5)).status == "fail"


async def test_loki_retention_disabled_is_unbounded_and_discovery():
    w = good_world()
    w["http"][f"{LOKI}/config"] = (200, "limits_config:\n  retention_period: 744h\ncompactor:\n"
                                        "  retention_enabled: false\n")
    out = await run_one(get_assertion("log-retention"), make_ctx(w), 5)
    assert out.status == "pass" and out.evidence["instances"][0]["unbounded"]
    w["k8s"]["/api/v1/services"] = []
    out = await run_one(get_assertion("log-retention"), make_ctx(w), 5)
    assert out.status == "fail" and "no Loki" in out.detail


async def test_registry_cluster_internal_anonymous_passes():
    w = good_world()
    w["http"][f"{REG}/v2/"] = (200, {})
    out = await run_one(get_assertion("reg-access-restricted"), make_ctx(w), 5)
    assert out.status == "pass" and "cluster-internal" in out.detail
    w["k8s"]["/apis/gateway.networking.k8s.io/v1/httproutes"].append(
        {"metadata": {"namespace": "container-registry", "name": "reg"},
         "spec": {"rules": [{"backendRefs": [{"name": "registry"}]}]}})
    assert (await run_one(get_assertion("reg-access-restricted"), make_ctx(w), 5)).status == "fail"


async def test_mfa_not_applicable_without_admin_group():
    w = good_world()
    w["keycloak"]["/groups"] = []
    assert (await run_one(get_assertion("kc-admin-mfa"), make_ctx(w), 5)).status == "not-applicable"


async def test_poam_not_needed_without_open_items():
    w = good_world()
    w["snapshot"].update(openFindings=0, postureFailures=[], latestPoam=None)
    assert (await run_one(get_assertion("pack-poam-current"), make_ctx(w), 5)).status == "pass"


async def test_http_error_types():
    w = good_world()
    w["http"][f"{PROM}/api/v1/targets"] = httpx.ReadTimeout("slow", request=httpx.Request("GET", PROM))
    out = await run_one(get_assertion("mon-prometheus-scraping"), make_ctx(w), 5)
    assert out.status == "unknown" and "ReadTimeout" in out.detail
