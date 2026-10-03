"""Fixtures for report generator tests.

`make_snapshot()` builds a realistic snapshot: 4 images (one kube-system), 7 workloads
(one in `default`), 3 scanners (one with a stale DB), ~30 consensus findings with mixed
agreement / fixability / ages (some past SLA), posture results for all 16 checks, and a
12-point trend. It validates through the real `posture.reports.models.ReportSnapshot` when
that model exists and accepts the data, else through the local contract stub.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).parent
SRC = HERE.parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
SCAN_START = NOW - timedelta(minutes=14)

CHECKS = [
    ("privileged", "critical", "Privileged container", "Set securityContext.privileged: false."),
    ("host-namespaces", "critical", "Pod shares host namespaces", "Remove hostPID/hostIPC/hostNetwork."),
    ("host-path", "high", "hostPath volume mounted", "Use PVCs or projected volumes instead of hostPath."),
    ("run-as-root", "high", "Container may run as root", "Set runAsNonRoot: true and a non-zero runAsUser."),
    ("privilege-escalation", "high", "Privilege escalation allowed", "Set allowPrivilegeEscalation: false."),
    ("added-capabilities", "high", "Capabilities added", "Remove capabilities.add entries."),
    ("capabilities-not-dropped", "medium", "Capabilities not dropped", "Set capabilities.drop: [ALL]."),
    ("writable-rootfs", "medium", "Writable root filesystem", "Set readOnlyRootFilesystem: true."),
    ("no-resource-limits", "medium", "No resource limits", "Set cpu and memory limits."),
    ("no-resource-requests", "low", "No resource requests", "Set cpu and memory requests."),
    ("mutable-tag", "medium", "Mutable image tag", "Pin images by digest."),
    ("no-liveness-probe", "low", "No liveness probe", "Add a livenessProbe."),
    ("no-readiness-probe", "low", "No readiness probe", "Add a readinessProbe."),
    ("automount-sa-token", "low", "Default SA token automounted", "Set automountServiceAccountToken: false."),
    ("seccomp-unconfined", "medium", "Seccomp unconfined", "Set seccompProfile.type: RuntimeDefault."),
    ("no-netpol", "low", "No NetworkPolicy", "Add a NetworkPolicy selecting the pod."),
]

IMAGES = [
    dict(id=1, ref="docker.io/library/nginx:1.25.3", registry="docker.io", repository="library/nginx", tag="1.25.3",
         digest="sha256:" + "a1" * 32, os="debian 12.4", score=41.2, grade="F", namespaces=["web", "default"],
         workloads=["web/Deployment/frontend", "default/Deployment/legacy-proxy"], packs=["web-pack"], containers=4),
    dict(id=2, ref="quay.io/nebari/nebari-jupyterhub:2024.11.1", registry="quay.io",
         repository="nebari/nebari-jupyterhub", tag="2024.11.1", digest="sha256:" + "b2" * 32, os="ubuntu 22.04",
         score=68.5, grade="C", namespaces=["dev"], workloads=["dev/Deployment/hub", "dev/StatefulSet/hub-db"],
         packs=["jupyterhub"], containers=3),
    dict(id=3, ref="docker.io/library/postgres:16-alpine", registry="docker.io", repository="library/postgres",
         tag="16-alpine", digest="sha256:" + "c3" * 32, os="alpine 3.19.1", score=88.0, grade="B",
         namespaces=["dev", "security-posture"], workloads=["dev/StatefulSet/hub-db",
                                                            "security-posture/StatefulSet/postgres"],
         packs=["jupyterhub", "security-posture"], containers=2),
    dict(id=4, ref="registry.k8s.io/coredns/coredns:v1.11.1", registry="registry.k8s.io",
         repository="coredns/coredns", tag="v1.11.1", digest="sha256:" + "d4" * 32, os="", score=95.3, grade="A",
         namespaces=["kube-system"], workloads=["kube-system/Deployment/coredns"], packs=[], containers=2),
    dict(id=5, ref="localhost:32000/private/app:latest", registry="localhost:32000", repository="private/app",
         tag="latest", digest="", os="", score=None, grade="?", namespaces=["dev"],
         workloads=["dev/Job/batch"], packs=[], containers=1, running=False,
         scanner_status={"trivy": "error", "grype": "error", "clair": "unsupported"},
         warnings=["mirror failed: unauthorized"]),
]

WORKLOADS = [
    ("web", "Deployment", "frontend", "web-pack", [1], 3),
    ("default", "Deployment", "legacy-proxy", None, [1], 1),
    ("dev", "Deployment", "hub", "jupyterhub", [2], 2),
    ("dev", "StatefulSet", "hub-db", "jupyterhub", [2, 3], 2),
    ("dev", "Job", "batch", None, [5], 1),
    ("security-posture", "StatefulSet", "postgres", "security-posture", [3], 1),
    ("kube-system", "Deployment", "coredns", None, [4], 2),
]

# (vuln, pkg, installed, fixed, severity, scanners, cvss, age_days, images)
VULNS = [
    ("CVE-2023-44487", "libnghttp2-14", "1.52.0-1", "1.52.0-1+deb12u1", "high", ["trivy", "grype", "clair"], 7.5, 200, [1]),
    ("CVE-2024-6387", "openssh-client", "1:9.2p1-2", "1:9.2p1-2+deb12u3", "critical", ["trivy", "grype"], 8.1, 40, [1]),
    ("CVE-2024-2961", "libc6", "2.36-9+deb12u4", "2.36-9+deb12u7", "high", ["trivy", "grype", "clair"], 7.3, 20, [1]),
    ("CVE-2023-52425", "libexpat1", "2.5.0-1", None, "high", ["trivy", "grype"], 7.5, 120, [1]),
    ("CVE-2024-45490", "libexpat1", "2.5.0-1", "2.5.0-1+deb12u1", "critical", ["trivy", "grype", "clair"], 9.8, 5, [1]),
    ("CVE-2023-4911", "libc6", "2.36-9+deb12u4", "2.36-9+deb12u3", "high", ["clair"], 7.8, 300, [1]),
    ("CVE-2024-0727", "openssl", "3.0.11-1~deb12u2", "3.0.13-1~deb12u1", "medium", ["trivy", "grype", "clair"], 5.5, 95, [1]),
    ("CVE-2023-5678", "openssl", "3.0.11-1~deb12u2", "3.0.13-1~deb12u1", "medium", ["trivy", "grype"], 5.3, 95, [1]),
    ("CVE-2024-28182", "libnghttp2-14", "1.52.0-1", "1.52.0-1+deb12u2", "medium", ["trivy", "grype", "clair"], 5.3, 30, [1]),
    ("CVE-2011-3374", "apt", "2.6.1", None, "negligible", ["trivy", "grype", "clair"], 3.7, 400, [1]),
    ("CVE-2022-0563", "util-linux", "2.38.1-5+b1", None, "low", ["trivy", "grype"], 5.5, 400, [1]),
    ("CVE-2024-3651", "idna", "3.4", "3.7", "medium", ["trivy", "grype"], 6.2, 60, [2]),
    ("CVE-2024-35195", "requests", "2.31.0", "2.32.0", "medium", ["trivy", "grype", "clair"], 5.6, 100, [2]),
    ("CVE-2024-6345", "setuptools", "68.0.0", "70.0.0", "high", ["trivy", "grype"], 8.8, 45, [2]),
    ("CVE-2024-22195", "jinja2", "3.1.2", "3.1.3", "medium", ["trivy", "grype", "clair"], 5.4, 250, [2]),
    ("CVE-2023-50782", "cryptography", "41.0.4", "42.0.0", "high", ["trivy"], 7.5, 10, [2]),
    ("CVE-2024-26130", "cryptography", "41.0.4", "42.0.4", "high", ["trivy", "grype"], 7.5, 33, [2]),
    ("GHSA-h4gh-qq45-vh27", "cryptography", "41.0.4", "43.0.1", "medium", ["grype"], 5.9, 12, [2]),
    ("CVE-2024-5535", "libssl3", "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.16", "low", ["trivy", "grype", "clair"], 9.1, 70, [2]),
    ("CVE-2016-2781", "coreutils", "8.32-4.1ubuntu1", None, "low", ["trivy", "grype", "clair"], 6.5, 500, [2]),
    ("CVE-2024-4741", "libssl3", "3.1.4-r5", "3.1.6-r0", "high", ["trivy", "grype", "clair"], 7.5, 16, [3]),
    ("CVE-2024-5535", "libssl3", "3.1.4-r5", "3.1.6-r0", "critical", ["trivy", "grype"], 9.1, 16, [3]),
    ("CVE-2023-6129", "libcrypto3", "3.1.4-r5", "3.1.4-r6", "medium", ["trivy", "grype", "clair"], 6.5, 250, [3]),
    ("CVE-2024-24790", "stdlib", "go1.21.5", "go1.21.11", "critical", ["trivy", "grype"], 9.8, 3, [3, 4]),
    ("CVE-2023-45288", "golang.org/x/net", "v0.17.0", "v0.23.0", "medium", ["trivy", "grype"], 7.5, 150, [4]),
    ("CVE-2024-24788", "stdlib", "go1.21.5", "go1.21.10", "medium", ["grype"], 7.5, 150, [4]),
    ("CVE-2023-39325", "golang.org/x/net", "v0.17.0", None, "high", ["trivy", "grype", "clair"], 7.5, 365, [4]),
]




def _findings() -> list[dict[str, Any]]:
    out = []
    for vid, pkg, inst, fixed, sev, scanners, cvss, age, imgs in VULNS:
        for img in imgs:
            per = {s: sev for s in scanners}
            if len(scanners) > 1 and sev == "high":
                per[scanners[-1]] = "medium"  # scanners disagree on severity
            out.append(dict(
                image_id=img, vuln_id=vid, severity=sev, package=pkg, installed_version=inst, fixed_version=fixed,
                pkg_type="deb" if "deb" in inst or "ubuntu" in inst else ("apk" if "-r" in inst else "python"),
                scanners=scanners, agreement=len(scanners) / 3, per_scanner=per, cvss=cvss,
                title=f"{pkg}: security issue tracked as {vid}",
                description=f"A flaw in {pkg} allows an attacker to compromise the affected service ({vid}).",
                url=f"https://nvd.nist.gov/vuln/detail/{vid}" if vid.startswith("CVE") else f"https://github.com/advisories/{vid}",
                fixable=fixed is not None, first_seen_at=NOW - timedelta(days=age),
            ))
    return out


def _posture() -> list[dict[str, Any]]:
    fails = {
        "web/Deployment/frontend": {"run-as-root", "writable-rootfs", "capabilities-not-dropped", "seccomp-unconfined",
                                    "no-netpol", "privilege-escalation"},
        "default/Deployment/legacy-proxy": {"privileged", "host-namespaces", "host-path", "added-capabilities",
                                            "run-as-root", "no-resource-limits", "no-resource-requests",
                                            "no-liveness-probe", "no-readiness-probe", "automount-sa-token",
                                            "mutable-tag", "no-netpol", "privilege-escalation"},
        "dev/Deployment/hub": {"writable-rootfs", "no-liveness-probe"},
        "dev/StatefulSet/hub-db": {"run-as-root", "writable-rootfs"},
        "dev/Job/batch": {"mutable-tag", "no-resource-limits"},
        "security-posture/StatefulSet/postgres": set(),
        "kube-system/Deployment/coredns": {"added-capabilities", "writable-rootfs"},
    }
    out = []
    for key, failed in fails.items():
        ns, kind, name = key.split("/")
        for cid, sev, _t, _r in CHECKS:
            st = "fail" if cid in failed else "pass"
            detail = ""
            if st == "fail":
                detail = {"added-capabilities": "capabilities.add: [NET_ADMIN]", "host-namespaces": "hostNetwork: true",
                          "host-path": "hostPath: /var/run/docker.sock"}.get(cid, "")
            out.append(dict(check_id=cid, status=st, namespace=ns, kind=kind, name=name,
                            container=name.split("-")[0], detail=detail,
                            severity="critical" if (cid == "added-capabilities" and ns == "default") else sev,
                            system_namespace=ns == "kube-system",
                            first_seen_at=NOW - timedelta(days=60 if ns == "default" else 10)))
    return out


def snapshot_data(**over: Any) -> dict[str, Any]:
    imgs = []
    for raw in IMAGES:
        i = dict(raw)
        fs = [f for f in _findings() if f["image_id"] == i["id"]]
        i.setdefault("counts", {s: sum(1 for f in fs if f["severity"] == s)
                                for s in ("critical", "high", "medium", "low", "negligible", "unknown")})
        i.setdefault("fixable", {s: sum(1 for f in fs if f["severity"] == s and f["fixable"])
                                 for s in ("critical", "high", "medium", "low", "negligible", "unknown")})
        i.setdefault("scanner_status", {"trivy": "ok", "grype": "ok", "clair": "ok" if i["id"] != 4 else "unsupported"})
        i.setdefault("running", True)
        i.setdefault("running_containers", i["containers"] if i["running"] else 0)
        i.setdefault("agreement_index", 0.8)
        i.setdefault("last_scanned_at", SCAN_START + timedelta(minutes=i["id"]))
        i.setdefault("mirrored", True)
        imgs.append(i)
    wls = [dict(namespace=ns, kind=k, name=n, pack=p, image_ids=ids, containers=c, running=k != "Job",
                score=70.0, grade="C") for ns, k, n, p, ids, c in WORKLOADS]
    data = dict(
        generated_at=NOW,
        system=dict(name="lab", organization="Quansight / Nebari Dev", cluster_name="lab-microk8s",
                    description="Nebari development platform on a single-node MicroK8s cluster.",
                    hostname="security.example.org", ip_address="192.0.2.10",
                    poc_name="Jane Example", poc_email="isso@example.org", emass_system_id="12345"),
        scan=dict(id=42, status="done", trigger="scheduled", started_at=SCAN_START, finished_at=NOW - timedelta(minutes=1),
                  requested_by="scheduler", score=63.4, grade="D", vuln_score=58.1, posture_score=75.8),
        scope=dict(kind="cluster"),
        sla_days={"critical": 15, "high": 30, "medium": 90, "low": 180},
        scanners=[
            dict(name="trivy", version="0.75.0", db_updated_at=NOW - timedelta(hours=5), healthy=True),
            dict(name="grype", version="0.104.0", db_updated_at=NOW - timedelta(hours=11), healthy=True),
            dict(name="clair", version="4.9.0", db_updated_at=NOW - timedelta(days=5), healthy=True),
        ],
        images=imgs,
        findings=_findings(),
        workloads=wls,
        checks=[dict(id=c, severity=s, title=t, remediation=r, description=f"{t}.") for c, s, t, r in CHECKS],
        posture_results=_posture(),
        trend=[dict(scan_id=30 + k, finished_at=NOW - timedelta(days=12 - k), score=s, grade=g, critical=c, high=h)
               for k, (s, g, c, h) in enumerate([(55.0, "D", 9, 20), (56.2, "D", 9, 19), (52.1, "D", 10, 22),
                                                 (58.0, "D", 8, 18), (60.3, "D", 7, 15), (61.0, "D", 7, 15),
                                                 (59.4, "D", 7, 16), (62.2, "D", 6, 14), (66.0, "C", 5, 12),
                                                 (64.8, "D", 5, 13), (63.0, "D", 5, 13), (63.4, "D", 5, 13)])],
    )
    data.update(over)
    return data


def _model():
    try:
        from posture.reports.models import ReportSnapshot  # type: ignore

        return ReportSnapshot
    except Exception:
        return None


def make_snapshot(**over: Any):
    """The real ReportSnapshot, validated. No silent fallback to the stub model: a factory that
    the real model rejects is model drift and must fail the test (quality review m8)."""
    real = _model()
    if real is None:
        raise RuntimeError("posture.reports.models.ReportSnapshot is not importable")
    return real.model_validate(snapshot_data(**over))


@pytest.fixture
def snapshot():
    return make_snapshot()


@pytest.fixture
def opts():
    return {"now": NOW}
