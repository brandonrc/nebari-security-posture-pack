"""Pod watcher (architecture review m11): unit tests for event parsing and debouncing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from posture.event_scans import PodWatcher, pod_age_seconds, pod_image_keys, pod_owned_by_job

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


# ------------------------------------------------------------------ hygiene (grace, 2026-10-05)
D3 = "sha256:" + "c" * 64
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def live_pod(ns, name, digest, *, age=600.0, owner=None, phase="Running", uid=None):
    p = pod(ns, (f"ghcr.io/o/{name}:1", f"ghcr.io/o/{name}@{digest}"))
    p["metadata"].update({"name": name, "uid": uid or name,
                          "creationTimestamp": (NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z")})
    if owner:
        p["metadata"]["ownerReferences"] = [{"kind": owner, "name": f"{name}-owner", "controller": True}]
    p["status"]["phase"] = phase
    return p


def hygienic(**kw):
    args = dict(debounce=60, quiet=10, interval=300, min_pod_age=120, include_jobs=False)
    args.update(kw)
    return PodWatcher(None, **args)


def test_job_pods_are_ignored_unless_included():
    assert pod_owned_by_job(live_pod("db", "backup", D1, owner="Job"))
    assert not pod_owned_by_job(live_pod("db", "pg", D1, owner="StatefulSet"))
    w = hygienic()
    ev = {"type": "ADDED", "object": live_pod("db", "backup", D1, owner="Job")}
    assert w.observe(ev, now=0, wall=NOW) == 0 and w.ignored["job"] == 1 and not w.pending
    assert hygienic(include_jobs=True).observe(ev, now=0, wall=NOW) == 1


def test_terminated_pods_are_ignored():
    w = hygienic()
    assert w.observe({"type": "MODIFIED", "object": live_pod("v", "verify", D1, phase="Succeeded")},
                     now=0, wall=NOW) == 0
    assert w.ignored["terminated"] == 1 and not w.pending


def test_young_pods_wait_and_short_lived_ones_never_trigger():
    w = hygienic()
    assert pod_age_seconds(live_pod("a", "x", D1, age=30), NOW) == 30
    # a verify pod: created, deleted 40 s later -> nothing
    w.observe({"type": "ADDED", "object": live_pod("v", "verify", D1, age=5)}, now=100, wall=NOW)
    assert not w.pending and "verify" in w.young
    w.observe({"type": "DELETED", "object": live_pod("v", "verify", D1, age=45)}, now=140, wall=NOW)
    assert w.promote(now=1000) == 0 and not w.pending and not w.young
    # a real workload: young at first, pending once it is 120 s old
    w.observe({"type": "ADDED", "object": live_pod("app", "web", D2, age=20)}, now=100, wall=NOW)
    assert w.promote(now=150) == 0 and not w.pending
    assert w.promote(now=200) == 1 and list(w.pending) == [f"ghcr.io/o/web@{D2}"]
    # pods without a creationTimestamp are treated as old enough
    p = pod("b", ("alpine", f"alpine@{D3}"))
    assert w.observe({"type": "ADDED", "object": p}, now=201, wall=NOW) == 1


def test_one_event_scan_per_interval():
    w = hygienic(min_pod_age=0)
    w.observe({"type": "ADDED", "object": live_pod("a", "one", D1)}, now=0, wall=NOW)
    assert w.due(11)
    w.pending.clear()
    w._last_flush = 11  # flushed at t=11
    w.observe({"type": "ADDED", "object": live_pod("b", "two", D2)}, now=20, wall=NOW)
    assert not w.due(100) and not w.due(310)  # quiet, but within 300 s of the previous event scan
    assert w.due(311)


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Session:
    def __init__(self, running):
        self.running = running

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, stmt):
        return _Rows([])  # none of the pending keys was scanned meanwhile

    async def scalar(self, stmt):
        return self.running


async def test_flush_waits_for_a_running_full_scan(monkeypatch):
    from posture import event_scans

    state = {"running": 1}
    enqueued = []

    async def fake_enqueue(sm, namespaces):
        enqueued.append(namespaces)
        return 42

    monkeypatch.setattr(event_scans, "enqueue_event_scan", fake_enqueue)
    w = PodWatcher(lambda: _Session(state["running"]), debounce=60, quiet=10, interval=300)
    w.observe({"type": "ADDED", "object": live_pod("a", "one", D1)}, now=0, wall=NOW)
    assert await w.flush(now=11) is None and enqueued == [] and w.pending  # deferred, keys kept
    assert not w.due(20) and w.due(41)  # retried every 30 s
    state["running"] = 0
    assert await w.flush(now=41) == 42 and enqueued == [["a"]] and not w.pending
