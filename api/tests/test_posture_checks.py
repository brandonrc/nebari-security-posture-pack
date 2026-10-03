from posture.inventory_model import InventorySnapshot, NetworkPolicyInfo
from posture.posture_checks import CHECKS, CHECKS_BY_ID, evaluate_inventory, evaluate_workload

HARDENED = {
    "container": {
        "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": True,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "resources": {"limits": {"cpu": "1", "memory": "1Gi"}, "requests": {"cpu": "100m", "memory": "128Mi"}},
        "livenessProbe": True, "readinessProbe": True,
    },
    "pod": {"hostPID": False, "hostIPC": False, "hostNetwork": False, "hostPathVolumes": [],
            "securityContext": {}, "automountServiceAccountToken": False, "serviceAccountName": "web"},
}


def by_id(results):
    return {(r.check_id, r.container): r for r in results}


def test_catalogue_matches_scoring_md():
    ids = {c.id for c in CHECKS}
    assert ids == {"privileged", "host-namespaces", "host-path", "run-as-root", "privilege-escalation",
                   "added-capabilities", "capabilities-not-dropped", "writable-rootfs", "no-resource-limits",
                   "no-resource-requests", "mutable-tag", "no-liveness-probe", "no-readiness-probe",
                   "automount-sa-token", "seccomp-unconfined", "no-netpol"}
    # probes are operational hygiene (compliance review M4): no control, no POA&M row
    assert all(c.controls for c in CHECKS if c.id not in ("no-liveness-probe", "no-readiness-probe"))
    assert not any(c.controls for c in CHECKS if c.id in ("no-liveness-probe", "no-readiness-probe"))
    assert CHECKS_BY_ID["privileged"].severity == "critical"


def test_hardened_container_passes_everything(container_factory):
    c = container_factory(security=HARDENED, image="ghcr.io/org/web:1.0")
    inv = InventorySnapshot([c], network_policies=[NetworkPolicyInfo("app", "default-deny", {})])
    results = evaluate_workload([c], inv)
    assert {r.status for r in results} == {"pass"}, [r for r in results if r.status == "fail"]
    assert len(results) == 16


def test_default_container_fails_expected(container_factory):
    c = container_factory(image="nginx")  # bare spec: nothing set
    inv = InventorySnapshot([c], network_policies=[])
    r = by_id(evaluate_workload([c], inv))
    failing = {k[0] for k, v in r.items() if v.status == "fail"}
    assert failing == {"run-as-root", "privilege-escalation", "capabilities-not-dropped", "writable-rootfs",
                       "no-resource-limits", "no-resource-requests", "mutable-tag", "no-liveness-probe",
                       "no-readiness-probe", "automount-sa-token", "seccomp-unconfined", "no-netpol"}


def test_privileged_hostns_hostpath_caps(container_factory):
    sec = {"container": {"securityContext": {"privileged": True, "capabilities": {"add": ["NET_ADMIN"]}}},
           "pod": {"hostNetwork": True, "hostPathVolumes": ["varlog"]}}
    c = container_factory(security=sec)
    r = by_id(evaluate_workload([c]))
    assert r[("privileged", "web")].status == "fail"
    assert r[("host-namespaces", "")].status == "fail"
    assert r[("host-path", "")].detail == "hostPath volumes: varlog"
    caps = r[("added-capabilities", "web")]
    assert caps.status == "fail" and caps.severity == "critical" and caps.weight == 10
    sec["container"]["securityContext"]["capabilities"]["add"] = ["NET_BIND_SERVICE"]
    caps = by_id(evaluate_workload([container_factory(security=sec)]))[("added-capabilities", "web")]
    assert caps.severity == "high" and caps.weight == 4


def test_run_as_root_inherits_pod_level(container_factory):
    sec = {"container": {}, "pod": {"securityContext": {"runAsUser": 1000}}}
    assert by_id(evaluate_workload([container_factory(security=sec)]))[("run-as-root", "web")].status == "pass"
    sec = {"container": {"securityContext": {"runAsUser": 0}}, "pod": {"securityContext": {"runAsNonRoot": False}}}
    assert by_id(evaluate_workload([container_factory(security=sec)]))[("run-as-root", "web")].status == "fail"


def test_seccomp_pod_level_and_unconfined(container_factory):
    sec = {"container": {}, "pod": {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}}
    assert by_id(evaluate_workload([container_factory(security=sec)]))[("seccomp-unconfined", "web")].status == "pass"
    sec["container"] = {"securityContext": {"seccompProfile": {"type": "Unconfined"}}}
    assert by_id(evaluate_workload([container_factory(security=sec)]))[("seccomp-unconfined", "web")].status == "fail"


def test_probes_not_required_for_jobs_and_init(container_factory):
    job = container_factory(workload_kind="Job", workload_name="migrate")
    r = by_id(evaluate_workload([job]))
    assert ("no-liveness-probe", "web") not in r
    init = container_factory(container="init", container_type="init")
    r = by_id(evaluate_workload([init, container_factory()]))
    assert ("no-liveness-probe", "init") not in r and ("no-liveness-probe", "web") in r


def test_ephemeral_containers_ignored(container_factory):
    dbg = container_factory(container="debugger", container_type="ephemeral",
                            security={"container": {"securityContext": {"privileged": True}}, "pod": {}})
    r = by_id(evaluate_workload([container_factory(), dbg]))
    assert ("privileged", "debugger") not in r


def test_netpol_selection_and_rbac_unknown(container_factory):
    c = container_factory(pod_labels={"app": "web", "tier": "fe"})
    other = NetworkPolicyInfo("app", "db-only", {"matchLabels": {"app": "db"}})
    expr = NetworkPolicyInfo("app", "fe", {"matchExpressions": [{"key": "tier", "operator": "In", "values": ["fe"]}]})
    assert by_id(evaluate_workload([c], InventorySnapshot([c], network_policies=[other])))[("no-netpol", "")].status == "fail"
    assert by_id(evaluate_workload([c], InventorySnapshot([c], network_policies=[other, expr])))[("no-netpol", "")].status == "pass"
    wrong_ns = NetworkPolicyInfo("elsewhere", "all", {})
    assert by_id(evaluate_workload([c], InventorySnapshot([c], network_policies=[wrong_ns])))[("no-netpol", "")].status == "fail"
    # netpols could not be listed -> check not evaluated
    assert ("no-netpol", "") not in by_id(evaluate_workload([c], InventorySnapshot([c], network_policies=None)))


def test_kube_system_half_weight_and_flag(container_factory):
    sec = {"container": {"securityContext": {"privileged": True}}, "pod": {}}
    c = container_factory(namespace="kube-system", security=sec)
    r = by_id(evaluate_workload([c]))[("privileged", "web")]
    assert r.weight == 5.0 and r.system_namespace


def test_representative_pod_dedupes_replicas(container_factory):
    pods = [container_factory(pod=f"web-{i}", running=i != 0) for i in range(3)]
    inv = InventorySnapshot(pods, network_policies=[])
    wp = evaluate_inventory(inv)[("app", "Deployment", "web")]
    assert {r.pod for r in wp.results} == {"web-1"}
    assert wp.failed == 11 and 0 < wp.score < 100
