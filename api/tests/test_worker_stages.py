"""Worker stages (--stages), the scan -> privileged-worker hand-off, and the DB-derived
scheduler (architecture review B2/B4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from posture import worker as worker_mod
from posture.worker import (
    ALL_STAGES,
    inventory_from_json,
    inventory_to_json,
    next_scheduled_scan,
    parse_stages,
)
from tests.test_integration import env, inventory, make_worker  # noqa: F401  (module fixture)

T0 = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


# ------------------------------------------------------------------ due computation
def test_first_scan_runs_immediately():
    assert next_scheduled_scan(None, None, 6, T0) == T0


def test_first_scan_can_wait_for_first_run():
    later = T0 + timedelta(hours=6)
    assert next_scheduled_scan(None, None, 6, T0, first_run=later) == later


def test_due_is_interval_after_last_done_start():
    last = T0 - timedelta(hours=2)
    assert next_scheduled_scan(last, None, 6, T0) == last + timedelta(hours=6)


def test_overdue_after_restart_is_due_now():
    # worker restarted every 2h for a day: the newest done scan is 20h old -> due in the past
    last = T0 - timedelta(hours=20)
    assert next_scheduled_scan(last, None, 6, T0) <= T0


def test_failed_attempt_backs_off_one_hour():
    last_done = T0 - timedelta(hours=10)
    failed = T0 - timedelta(minutes=10)
    assert next_scheduled_scan(last_done, failed, 6, T0) == failed + timedelta(hours=1)
    # with no successful scan at all
    assert next_scheduled_scan(None, failed, 6, T0) == failed + timedelta(hours=1)
    # an older failure does not matter
    assert next_scheduled_scan(last_done, last_done - timedelta(hours=1), 6, T0) == last_done + timedelta(hours=6)
    # short intervals back off by the interval, not an hour
    assert next_scheduled_scan(None, failed, 0.25, T0) == failed + timedelta(minutes=15)


def test_parse_stages():
    assert parse_stages(None) == frozenset(ALL_STAGES)
    assert parse_stages("") == frozenset(ALL_STAGES)
    assert parse_stages("all") == frozenset(ALL_STAGES)
    assert parse_stages("inventory, scan") == {"inventory", "scan"}
    assert parse_stages(["provenance", "controls", "reports"]) == {"provenance", "controls", "reports"}
    with pytest.raises(ValueError, match="unknown worker stage"):
        parse_stages("inventory,scna")


def test_cli_rejects_unknown_stage():
    with pytest.raises(ValueError):
        worker_mod.main(["--stages", "bogus"])


def test_inventory_round_trip():
    inv = inventory()
    inv.containers[0].image_key = "ghcr.io/org/web@sha256:" + "2" * 64
    back = inventory_from_json(inventory_to_json(inv))
    assert back == inv
    inv.network_policies = None
    assert inventory_from_json(inventory_to_json(inv)).network_policies is None


def test_views_and_worker_agree_on_active_statuses():
    from posture.views import ACTIVE_SCAN_STATUSES

    assert set(ACTIVE_SCAN_STATUSES) == {"queued", "running", worker_mod.STATUS_SCANNED,
                                         worker_mod.STATUS_FINALIZING}


# ------------------------------------------------------------------ hand-off (Postgres)
def staged(env, stages):  # noqa: F811
    w = make_worker(env)
    return worker_mod.Worker(w.s, w.sm, scanners=w.scanners, inventory_fn=w.inventory_fn, mirror=w.mirror,
                             stages=stages)


@pytest.mark.integration
async def test_split_workers_hand_off(env):  # noqa: F811
    from sqlalchemy import select

    from posture.db.models import Scan, ScanSnapshot

    c = env["client"]
    scan_id = (await c.post("/scans", json={})).json()["id"]
    scanner = staged(env, "inventory,scan")
    privileged = staged(env, "provenance,controls,reports")
    assert scanner.provenance_stage is None and privileged.provenance_stage is not None
    assert scanner.heartbeat_id != privileged.heartbeat_id

    # privileged worker has nothing to do until the scan stage finished
    assert await privileged.poll_once() is False
    assert await scanner.poll_once() is True
    async with env["sm"]() as s:
        row = await s.get(Scan, scan_id)
        assert row.status == "scanned" and row.finished_at is None
        handoff = (await s.execute(select(ScanSnapshot).where(ScanSnapshot.scan_id == scan_id,
                                                              ScanSnapshot.level == "inventory"))).scalar_one()
        assert len(handoff.data["containers"]) == 5
        cluster = (await s.execute(select(ScanSnapshot).where(ScanSnapshot.scan_id == scan_id,
                                                              ScanSnapshot.level == "cluster"))).first()
        assert cluster is None
    # clients see an in-flight scan; a second full scan is refused meanwhile
    shown = (await c.get(f"/scans/{scan_id}")).json()
    assert shown["status"] == "running" and shown["phase"] == "scanned"
    assert (await c.post("/scans", json={})).status_code == 409
    assert [x["id"] for x in (await c.get("/scans", params={"status": "running"})).json()] == [scan_id]
    # the scan worker never finalizes
    assert await scanner.poll_once() is False

    assert await privileged.poll_once() is True
    scan = (await c.get(f"/scans/{scan_id}")).json()
    assert scan["status"] == "done", scan
    assert scan["imagesDone"] == 3 and scan["score"] is not None
    assert any("cluster score" in line for line in scan["log"])
    assert any("scan stage finished" in line for line in scan["log"])
    async with env["sm"]() as s:
        assert (await s.execute(select(ScanSnapshot).where(ScanSnapshot.scan_id == scan_id,
                                                           ScanSnapshot.level == "inventory"))).first() is None
    assert (await c.get("/summary")).json()["score"] is not None


@pytest.mark.integration
async def test_recover_finalizing_and_scheduler(env):  # noqa: F811
    from sqlalchemy import update

    from posture.db.models import Scan

    c = env["client"]
    scan_id = (await c.post("/scans", json={})).json()["id"]
    scanner = staged(env, "inventory,scan")
    assert await scanner.poll_once() is True
    async with env["sm"]() as s, s.begin():
        await s.execute(update(Scan).where(Scan.id == scan_id).values(status="finalizing"))
    privileged = staged(env, "provenance,controls,reports")
    await privileged.recover_stale()  # no posture snapshot yet -> retried
    async with env["sm"]() as s:
        assert (await s.get(Scan, scan_id)).status == "scanned"
    assert await privileged.poll_once() is True
    assert (await c.get(f"/scans/{scan_id}")).json()["status"] == "done"

    # scheduler: a done scan just started -> next due one interval later, nothing enqueued
    due = await scanner.next_scan_due()
    async with env["sm"]() as s:
        started = (await s.get(Scan, scan_id)).started_at
    assert due == started + timedelta(hours=scanner.s.scan_interval_hours)
    assert await scanner.maybe_enqueue_scheduled() is None
    # ... and due immediately once the newest done scan is older than the interval
    async with env["sm"]() as s, s.begin():
        await s.execute(update(Scan).values(started_at=Scan.started_at - timedelta(days=30)))
    new_id = await scanner.maybe_enqueue_scheduled()
    assert new_id is not None
    async with env["sm"]() as s:
        assert (await s.get(Scan, new_id)).trigger == "scheduled"
    assert await privileged.maybe_enqueue_scheduled() is None  # only the scan side schedules
