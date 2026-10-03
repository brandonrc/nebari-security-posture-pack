"""Pod watcher (architecture review m11): unit tests for event parsing and debouncing."""

from __future__ import annotations

from posture.event_scans import PodWatcher, pod_image_keys

D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64


def pod(ns, *statuses, init=()):
    return {"metadata": {"namespace": ns, "name": "p"},
            "status": {"containerStatuses": [{"image": i, "imageID": iid} for i, iid in statuses],
                       "initContainerStatuses": [{"image": i, "imageID": iid} for i, iid in init]}}


def test_pod_image_keys():
    p = pod("app", ("ghcr.io/o/web:1", f"ghcr.io/o/web@{D1}"), ("busybox", ""),
            init=(("alpine:3", f"docker-pullable://alpine@{D2}"),))
    assert pod_image_keys(p) == [(f"ghcr.io/o/web@{D1}", "app"), (f"docker.io/library/alpine@{D2}", "app")]
    assert pod_image_keys({"metadata": {"namespace": "x"}, "status": {}}) == []


def test_observe_and_debounce():
    w = PodWatcher(None, excluded_namespaces=lambda: ["kube-system"], debounce=60, quiet=10)
    w.known = {f"ghcr.io/o/web@{D1}"}
    assert w.observe({"type": "ADDED", "object": pod("app", ("ghcr.io/o/web:1", f"ghcr.io/o/web@{D1}"))}) == 0
    assert w.observe({"type": "DELETED", "object": pod("app", ("alpine", f"alpine@{D2}"))}) == 0
    assert w.observe({"type": "ADDED", "object": pod("kube-system", ("alpine", f"alpine@{D2}"))}) == 0
    assert not w.due()
    assert w.observe({"type": "MODIFIED", "object": pod("batch", ("alpine", f"alpine@{D2}"))}) == 1
    assert w.observe({"type": "MODIFIED", "object": pod("batch", ("alpine", f"alpine@{D2}"))}) == 0  # once
    first = w._first
    assert not w.due(first + 5)
    assert w.due(first + 10.5)  # quiet for 10 s
    w._last = first + 55  # a steady trickle of new keys still flushes 60 s after the first one
    assert not w.due(first + 59) and w.due(first + 60)
