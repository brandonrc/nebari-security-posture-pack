"""B2: the Kubernetes -> ContainerRecord adapter, driven by raw `kubectl get -o json` shapes.

tests/fixtures/k8s/cluster.json holds trimmed, redacted pods/ReplicaSets/Jobs/NebariApps from a
lab cluster plus a few crafted pods (native sidecar + ephemeral debug container, Windows). Every
posture check, workload score and STIG/SAR row is computed from this adapter's output, so these
tests go through the real code path: build_containers -> evaluate_inventory.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from posture import inventory
from posture.inventory import (
    build_containers,
    host_process,
    map_pack,
    parse_nebariapps,
    pod_os,
    resolve_owner,
)
from posture.inventory_model import InventorySnapshot, NebariAppInfo
from posture.posture_checks import evaluate_inventory, evaluate_workload

FIXTURE = Path(__file__).parent / "fixtures" / "k8s" / "cluster.json"


@pytest.fixture(scope="module")
def cluster() -> dict:
    return json.loads(FIXTURE.read_text())


def _index(items):
    return {(i["metadata"]["namespace"], i["metadata"]["name"]): i for i in items}


@pytest.fixture(scope="module")
def records(cluster):
    apps = parse_nebariapps(cluster["nebariapps"])
    return build_containers(cluster["pods"], _index(cluster["replicasets"]), _index(cluster["jobs"]), apps, set())


def _pod(records, name):
    out = [r for r in records if r.pod == name]
    assert out, f"no records for pod {name}"
    return out


def _results(records, pod_name, inv=None):
    return {(r.check_id, r.container): r for r in evaluate_workload(_pod(records, pod_name), inv)}


# ---------------------------------------------------------------- owners / workload identity

@pytest.mark.parametrize(("pod", "kind", "name"), [
    ("coredns-869c66859c-6crgv", "Deployment", "coredns"),                      # Pod -> RS -> Deployment
    ("coredns-77f6b8c9d4-abcde", "Deployment", "coredns"),                      # RS invisible: hash heuristic
    ("keycloak-realm-backup-29849870-vzdm4", "CronJob", "keycloak-realm-backup"),  # Pod -> Job -> CronJob
    ("lgtm-pack-loki-0", "StatefulSet", "lgtm-pack-loki"),
    ("calico-node-k8dzl", "DaemonSet", "calico-node"),
    ("user-a-nb", "Pod", "user-a-nb"),                                          # no ownerReferences
    ("win-web-6d9f7c5b8-k2m4n", "Deployment", "win-web"),
])
def test_workload_identity(records, pod, kind, name):
    r = _pod(records, pod)[0]
    assert (r.workload_kind, r.workload_name) == (kind, name)


def test_resolve_owner_edge_cases():
    # no controller flag: the first owner wins; RS without its own owner stays a ReplicaSet
    pod = {"metadata": {"namespace": "a", "name": "p", "ownerReferences": [{"kind": "ReplicaSet", "name": "rs1"}]}}
    rs = {("a", "rs1"): {"metadata": {"name": "rs1"}}}
    assert resolve_owner(pod, rs, {}) == ("ReplicaSet", "rs1")
    # invisible RS whose name does not end with the pod-template-hash: left as is
    pod["metadata"]["labels"] = {"pod-template-hash": "zzz"}
    assert resolve_owner(pod, {}, {}) == ("ReplicaSet", "rs1")
    # invisible Job: no heuristic
    job_pod = {"metadata": {"namespace": "a", "name": "j-x", "ownerReferences": [{"kind": "Job", "name": "j", "controller": True}]}}
    assert resolve_owner(job_pod, {}, {}) == ("Job", "j")
    # empty metadata
    assert resolve_owner({}, {}, {}) == ("Pod", "")


# ---------------------------------------------------------------- container walk

def test_every_container_type_is_recorded(records):
    hub = _pod(records, "hub-55b55d46b6-5p64v")
    types = {(r.container, r.container_type) for r in hub}
    assert ("hub", "container") in types
    assert ("log-shipper", "init") in types          # native sidecar
    assert ("debugger-x7k2p", "ephemeral") in types  # kubectl debug container
    dbg = next(r for r in hub if r.container_type == "ephemeral")
    assert dbg.image_id == "docker.io/library/busybox@sha256:" + "e" * 64  # from ephemeralContainerStatuses


def test_counts_and_running_flags(records, cluster):
    assert len({r.pod for r in records}) == len(cluster["pods"])
    expected = sum(len(p["spec"].get(k) or []) for p in cluster["pods"]
                   for k in ("containers", "initContainers", "ephemeralContainers"))
    assert len(records) == expected
    failed = _pod(records, "artifact-keeper-scanner-adapter-65c6456d5f-4ccmw")
    assert all(not r.running and r.pod_phase == "Failed" for r in failed)
    assert all(r.running for r in _pod(records, "lgtm-pack-loki-0"))


def test_image_id_comes_from_status_and_falls_back(records):
    api = [r for r in _pod(records, "security-posture-api-f6cf58b56-f78zl") if r.container_type == "container"][0]
    assert api.image_id and "@sha256:" in api.image_id
    # a container without a status entry: image from the spec, no image_id
    pods = [{"metadata": {"name": "p", "namespace": "n"}, "spec": {"containers": [{"name": "c", "image": "x:1"}]}}]
    (r,) = build_containers(pods, {}, {}, [], set())
    assert (r.image, r.image_id, r.pod_phase, r.running) == ("x:1", None, "Unknown", False)


def test_excluded_namespaces_are_skipped(cluster):
    recs = build_containers(cluster["pods"], {}, {}, [], {"kube-system", "win-apps"})
    assert not {r.namespace for r in recs} & {"kube-system", "win-apps"}


def test_security_snapshot_shape(records):
    calico = [r for r in _pod(records, "calico-node-k8dzl") if r.container_type == "container"][0]
    pod = calico.security["pod"]
    assert pod["hostNetwork"] is True and "lib-modules" in pod["hostPathVolumes"]
    assert pod["os"] == "linux"  # from the kubernetes.io/os nodeSelector
    assert calico.security["container"]["hostProcess"] is False
    bare = _pod(records, "checkmaite-nebari-checkmaite-pack-ui-5986bc89d-5pbk5")[0]
    assert bare.security["container"]["securityContext"] == {} and bare.security["pod"]["securityContext"] == {}
    assert bare.security["pod"]["automountServiceAccountToken"] is False
    assert _pod(records, "user-a-nb")[0].security["pod"]["serviceAccountName"] == "default"


# ---------------------------------------------------------------- pack mapping

def test_pack_mapping(records):
    assert {r.pack for r in _pod(records, "security-posture-api-f6cf58b56-f78zl")} == {"Security Posture"}
    assert {r.pack for r in _pod(records, "hub-55b55d46b6-5p64v")} == {"JupyterHub"}
    assert {r.pack for r in _pod(records, "coredns-869c66859c-6crgv")} == {None}


def test_map_pack_prefers_instance_then_display_name():
    apps = [NebariAppInfo("ns", "b-api", None, "b"), NebariAppInfo("ns", "b-ui", "B UI", "b"),
            NebariAppInfo("ns", "c", None, "c")]
    assert map_pack("ns", {"app.kubernetes.io/instance": "b"}, apps) == "B UI"
    assert map_pack("ns", {"release": "c"}, apps) == "c"
    assert map_pack("ns", {}, apps) == "B UI"  # namespace fallback: displayName first
    assert map_pack("other", {}, apps) is None


def test_parse_nebariapps(cluster):
    apps = {a.name: a for a in parse_nebariapps(cluster["nebariapps"])}
    sp = apps["security-posture"]
    assert (sp.namespace, sp.display_name, sp.instance, sp.pack) == ("security-posture", "Security Posture",
                                                                     "security-posture", "Security Posture")
    assert sp.hostname.endswith(".example.org")
    assert parse_nebariapps([{}])[0].pack == ""


# ---------------------------------------------------------------- end-to-end posture through the adapter

def test_privileged_daemonset(records):
    res = _results(records, "calico-node-k8dzl")
    assert res[("privileged", "calico-node")].status == "fail"
    assert res[("host-namespaces", "")].status == "fail"
    assert res[("host-path", "")].status == "fail"


def test_no_security_context_fails_the_baseline(records):
    res = _results(records, "checkmaite-nebari-checkmaite-pack-ui-5986bc89d-5pbk5")
    for check in ("run-as-root", "privilege-escalation", "capabilities-not-dropped", "writable-rootfs",
                  "seccomp-unconfined"):
        assert res[(check, "ui")].status == "fail", check
    assert res[("mutable-tag", "ui")].status == "fail"     # :latest
    assert res[("automount-sa-token", "")].status == "pass"  # dedicated SA, automount false
    bare = _results(records, "user-a-nb")
    assert bare[("automount-sa-token", "")].status == "fail"  # default SA, automount unset


def test_hardened_pack_pod(records):
    res = _results(records, "security-posture-api-f6cf58b56-f78zl")
    for check in ("privileged", "run-as-root", "privilege-escalation", "capabilities-not-dropped",
                  "writable-rootfs", "seccomp-unconfined"):
        assert res[(check, "api")].status == "pass", (check, res[(check, "api")].detail)


def test_native_sidecar_is_probed_and_ephemeral_is_not_scored(records):
    res = _results(records, "hub-55b55d46b6-5p64v")
    # restartPolicy Always init container is long-running: probe checks apply
    assert ("no-liveness-probe", "log-shipper") in res
    # the privileged debug container is not part of the workload template
    assert not any(container == "debugger-x7k2p" for _, container in res)


def test_job_pods_skip_probe_checks(records):
    res = _results(records, "keycloak-realm-backup-29849870-vzdm4")
    assert not any(check in ("no-liveness-probe", "no-readiness-probe") for check, _ in res)


def test_evaluate_inventory_groups_by_workload(records):
    inv = InventorySnapshot(records, network_policies=None)
    postures = evaluate_inventory(inv)
    assert ("kube-system", "Deployment", "coredns") in postures
    assert ("dns-test", "Deployment", "coredns") in postures
    assert ("keycloak", "CronJob", "keycloak-realm-backup") in postures
    # network_policies=None (RBAC denied): no-netpol is skipped, not failed
    assert not any(r.check_id == "no-netpol" for p in postures.values() for r in p.results)
    for p in postures.values():
        assert 0 <= p.score <= 100


# ---------------------------------------------------------------- Windows (B2)

LINUX_ONLY = ("privilege-escalation", "added-capabilities", "capabilities-not-dropped", "writable-rootfs",
              "seccomp-unconfined")


def test_pod_os_detection():
    assert pod_os({"os": {"name": "Windows"}}) == "windows"
    assert pod_os({"nodeSelector": {"kubernetes.io/os": "windows"}}) == "windows"
    assert pod_os({"os": {"name": "linux"}, "nodeSelector": {"kubernetes.io/os": "windows"}}) == "linux"
    assert pod_os({}) is None


def test_host_process_container_overrides_pod():
    pod = {"securityContext": {"windowsOptions": {"hostProcess": True}}}
    assert host_process(pod, {}) is True
    assert host_process(pod, {"securityContext": {"windowsOptions": {"hostProcess": False}}}) is False
    assert host_process({}, {"securityContext": {"windowsOptions": {"hostProcess": True}}}) is True
    assert host_process({}, {}) is False


def test_windows_pod_skips_linux_only_checks(records):
    (rec,) = _pod(records, "win-web-6d9f7c5b8-k2m4n")
    assert rec.security["pod"]["os"] == "windows"
    res = _results(records, "win-web-6d9f7c5b8-k2m4n")
    for check in LINUX_ONLY:
        assert (check, "app") not in res, f"{check} must be n/a on Windows"
    assert res[("privileged", "app")].status == "pass"
    # runAsUserName ContainerUser: not ContainerAdministrator
    assert res[("run-as-root", "app")].status == "pass"
    # still evaluated on Windows
    for check in ("no-resource-limits", "no-resource-requests", "mutable-tag", "no-liveness-probe"):
        assert res[(check, "app")].status == "pass", check
    assert {r.status for r in res.values()} == {"pass"}


def test_windows_host_process_is_privileged(records):
    res = _results(records, "win-host-agent-q8x2z")
    priv = res[("privileged", "app")]
    assert priv.status == "fail" and "hostProcess" in priv.detail and priv.severity == "critical"
    assert res[("host-namespaces", "")].status == "fail"  # hostProcess requires hostNetwork


def test_windows_run_as_root(container_factory):
    def rec(sc=None, psc=None):
        return container_factory(security={"container": {"securityContext": sc or {}},
                                           "pod": {"os": "windows", "securityContext": psc or {}}})
    admin = rec(sc={"windowsOptions": {"runAsUserName": "ContainerAdministrator"}})
    assert _check(admin, "run-as-root").status == "fail"
    assert _check(rec(psc={"runAsNonRoot": True}), "run-as-root").status == "pass"
    assert _check(rec(), "run-as-root") is None  # image default user: unknown, not a fail


def _check(c, check_id):
    return next((r for r in evaluate_workload([c]) if r.check_id == check_id), None)


# ---------------------------------------------------------------- collect_sync against a fake API

class _ApiException(Exception):
    def __init__(self, status, reason="Forbidden"):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _paged(items, page=5):
    """A list_* function that pages like the API server (limit/_continue)."""
    def fn(limit=500, _continue=None, **_):
        start = int(_continue or 0)
        chunk = items[start:start + min(limit, page)]
        nxt = start + len(chunk)
        return {"items": chunk, "metadata": {"continue": str(nxt) if nxt < len(items) else None}}
    return fn


def _denied(*_, **__):
    raise _ApiException(403)


@pytest.fixture
def fake_kube(monkeypatch, cluster):
    import kubernetes.client as kclient
    import kubernetes.client.exceptions as kexc

    state = {"netpol": _paged([{"metadata": {"namespace": "security-posture", "name": "default-deny"},
                                "spec": {"podSelector": {}}}]),
             "rs": _paged(cluster["replicasets"]),
             "apps": lambda *a, **k: {"items": cluster["nebariapps"]},
             "ns": _paged([{"metadata": {"name": n, "labels": {"nebari.dev/managed": "true"}}}
                           for n in sorted({p["metadata"]["namespace"] for p in cluster["pods"]})])}
    monkeypatch.setattr(kexc, "ApiException", _ApiException)
    monkeypatch.setattr(inventory, "_load_kube_config", lambda: None)
    monkeypatch.setattr(kclient, "CoreV1Api", lambda: SimpleNamespace(
        list_pod_for_all_namespaces=_paged(cluster["pods"]), list_namespace=lambda **k: state["ns"](**k)))
    monkeypatch.setattr(kclient, "AppsV1Api", lambda: SimpleNamespace(
        list_replica_set_for_all_namespaces=lambda **k: state["rs"](**k)))
    monkeypatch.setattr(kclient, "BatchV1Api", lambda: SimpleNamespace(list_job_for_all_namespaces=_paged(cluster["jobs"])))
    monkeypatch.setattr(kclient, "NetworkingV1Api", lambda: SimpleNamespace(
        list_network_policy_for_all_namespaces=lambda **k: state["netpol"](**k)))
    monkeypatch.setattr(kclient, "CustomObjectsApi", lambda: SimpleNamespace(
        list_cluster_custom_object=lambda *a, **k: state["apps"](*a, **k)))
    return state


def test_collect_sync_pages_and_builds(fake_kube, cluster):
    snap = inventory.collect_sync(["kube-system"])
    assert snap.errors == []
    assert "kube-system" not in snap.namespaces and snap.namespaces["jupyter"].managed
    assert not any(c.namespace == "kube-system" for c in snap.containers)
    assert snap.network_policies and snap.network_policies[0].name == "default-deny"
    assert {a.name for a in snap.nebari_apps} == {a["metadata"]["name"] for a in cluster["nebariapps"]}
    # owners resolved through the paged ReplicaSet list
    assert any(c.workload_kind == "Deployment" and c.workload_name == "win-web" for c in snap.containers)
    assert snap.collected_at is not None


def test_collect_sync_partial_rbac(fake_kube):
    def apps_404(*a, **k):
        raise _ApiException(404, "Not Found")
    fake_kube.update(netpol=_denied, rs=_denied, ns=_denied, apps=apps_404)
    snap = inventory.collect_sync()
    assert snap.network_policies is None  # no-netpol check is skipped downstream
    assert any(e.startswith("networkpolicies: 403") for e in snap.errors)
    assert any(e.startswith("replicasets: 403") for e in snap.errors)
    assert any(e.startswith("namespaces: 403") for e in snap.errors)
    assert not any(e.startswith("nebariapps") for e in snap.errors)  # CRD not installed: silent
    assert snap.nebari_apps == [] and snap.containers
    # RS list denied: Deployment still inferred from pod-template-hash
    assert any(c.workload_kind == "Deployment" for c in snap.containers)


def test_collect_sync_nebariapps_forbidden_is_reported(fake_kube):
    fake_kube["apps"] = _denied
    snap = inventory.collect_sync()
    assert any(e.startswith("nebariapps: 403") for e in snap.errors)


async def test_collect_logs_partial_errors(fake_kube):
    fake_kube["netpol"] = _denied
    snap = await inventory.collect()
    assert snap.network_policies is None and snap.errors


def test_list_all_sanitizes_client_objects(monkeypatch):
    class Obj:
        pass
    monkeypatch.setattr(inventory, "_sanitize", lambda o: {"items": [{"metadata": {"name": "x"}}], "metadata": {}})
    assert inventory._list_all(lambda **k: Obj()) == [{"metadata": {"name": "x"}}]


def test_load_kube_config_falls_back_to_kubeconfig(monkeypatch):
    from kubernetes import config

    calls = []

    def incluster():
        calls.append("incluster")
        raise config.ConfigException("not in a pod")

    monkeypatch.setattr(config, "load_incluster_config", incluster)
    monkeypatch.setattr(config, "load_kube_config", lambda: calls.append("kubeconfig"))
    inventory._load_kube_config()
    assert calls == ["incluster", "kubeconfig"]


def test_sanitize_uses_the_api_client():
    from kubernetes.client import V1ObjectMeta

    assert inventory._sanitize(V1ObjectMeta(name="x", namespace="y")) == {"name": "x", "namespace": "y"}
