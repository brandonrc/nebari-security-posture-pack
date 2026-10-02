"""Workload / namespace / cluster aggregation per docs/SCORING.md (pure functions)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .inventory_model import ContainerRecord, InventorySnapshot
from .posture_checks import WorkloadPosture
from .scoring import SYSTEM_NAMESPACES, combine, grade, mean, weighted_mean
from .severity import SEVERITIES, zero_counts


@dataclass
class ImageInfo:
    id: int
    ref: str
    score: float | None
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class WorkloadAgg:
    namespace: str
    kind: str
    name: str
    pack: str | None
    score: float | None
    grade: str
    vuln_score: float | None
    posture_score: float | None
    containers: int
    running_containers: int
    image_ids: list[int]
    posture_passed: int
    posture_failed: int
    counts: dict[str, int]
    system_namespace: bool


@dataclass
class NamespaceAgg:
    name: str
    pack: str | None
    managed: bool
    score: float | None
    grade: str
    workloads: int
    images: int
    counts: dict[str, int]
    posture: dict[str, int]
    containers: int
    running_containers: int


@dataclass
class ClusterAgg:
    score: float | None
    grade: str
    vuln_score: float | None
    posture_score: float | None
    workloads: int
    namespaces: int
    containers: int
    running_containers: int


def _sum_counts(images: list[ImageInfo]) -> dict[str, int]:
    out = zero_counts()
    for img in images:
        for s in SEVERITIES:
            out[s] += int((img.counts or {}).get(s, 0))
    return out


def aggregate(inv: InventorySnapshot, images_by_key: dict[str, ImageInfo],
              posture: dict[tuple[str, str, str], WorkloadPosture]) -> tuple[list[WorkloadAgg], list[NamespaceAgg], ClusterAgg]:
    groups: dict[tuple[str, str, str], list[ContainerRecord]] = {}
    for c in inv.containers:
        groups.setdefault((c.namespace, c.workload_kind, c.workload_name), []).append(c)

    workloads: list[WorkloadAgg] = []
    for key, cs in sorted(groups.items()):
        ns, kind, name = key
        running = [c for c in cs if c.running and c.container_type != "ephemeral"]
        basis = running or [c for c in cs if c.container_type != "ephemeral"] or cs
        imgs = [images_by_key[c.image_key] for c in basis if c.image_key in images_by_key]
        vuln = mean([i.score for i in imgs if i.score is not None])
        wp = posture.get(key)
        pscore = wp.score if wp and wp.results else None
        score = combine(vuln, pscore)
        uniq: dict[int, ImageInfo] = {}
        for c in cs:
            if c.image_key in images_by_key:
                i = images_by_key[c.image_key]
                uniq[i.id] = i
        packs = Counter(c.pack for c in cs if c.pack)
        workloads.append(WorkloadAgg(
            namespace=ns, kind=kind, name=name, pack=packs.most_common(1)[0][0] if packs else None,
            score=score, grade=grade(score), vuln_score=vuln, posture_score=pscore,
            containers=len([c for c in cs if c.container_type != "ephemeral"]),
            running_containers=len(running),
            image_ids=sorted(uniq), posture_passed=wp.passed if wp else 0, posture_failed=wp.failed if wp else 0,
            counts=_sum_counts(list(uniq.values())), system_namespace=ns in SYSTEM_NAMESPACES,
        ))

    any_running = any(w.running_containers for w in workloads)

    def weight(w: WorkloadAgg) -> float:
        return float(w.running_containers if any_running else w.containers)

    namespaces: list[NamespaceAgg] = []
    ns_names = sorted({w.namespace for w in workloads} | set(inv.namespaces))
    for ns in ns_names:
        ws = [w for w in workloads if w.namespace == ns]
        ns_any_running = any(w.running_containers for w in ws)
        score = weighted_mean((w.score, float(w.running_containers if ns_any_running else w.containers)) for w in ws)
        uniq: dict[int, ImageInfo] = {}
        for c in inv.containers:
            if c.namespace == ns and c.image_key in images_by_key:
                i = images_by_key[c.image_key]
                uniq[i.id] = i
        packs = Counter(w.pack for w in ws if w.pack)
        nsinfo = inv.namespaces.get(ns)
        app_pack = next((a.pack for a in sorted(inv.nebari_apps, key=lambda a: (a.display_name is None, a.name))
                         if a.namespace == ns), None)
        namespaces.append(NamespaceAgg(
            name=ns, pack=app_pack or (packs.most_common(1)[0][0] if packs else None),
            managed=bool(nsinfo and nsinfo.managed), score=score, grade=grade(score), workloads=len(ws),
            images=len(uniq), counts=_sum_counts(list(uniq.values())),
            posture={"passed": sum(w.posture_passed for w in ws), "failed": sum(w.posture_failed for w in ws)},
            containers=sum(w.containers for w in ws), running_containers=sum(w.running_containers for w in ws),
        ))

    vuln_pairs = []
    for c in inv.containers:
        if c.container_type == "ephemeral" or (any_running and not c.running):
            continue
        img = images_by_key.get(c.image_key or "")
        if img and img.score is not None:
            vuln_pairs.append((img.score, 1.0))
    vuln = weighted_mean(vuln_pairs)
    post = weighted_mean((w.posture_score, weight(w)) for w in workloads)
    score = combine(vuln, post)
    cluster = ClusterAgg(
        score=score, grade=grade(score), vuln_score=vuln, posture_score=post, workloads=len(workloads),
        namespaces=len([n for n in namespaces if n.workloads]),
        containers=sum(w.containers for w in workloads), running_containers=sum(w.running_containers for w in workloads),
    )
    return workloads, namespaces, cluster


def as_dict(obj: Any) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(obj)
