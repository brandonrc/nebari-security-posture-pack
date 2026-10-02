"""Scan readiness gate: wait for the grype DB and Clair's initial updaters before scanning."""

from __future__ import annotations

from posture import worker as worker_mod
from posture.app_settings import AppSettings
from posture.config import Settings
from posture.scanners import ClairScanner, GrypeScanner


class Grype(GrypeScanner):
    def __init__(self, states):
        self.states = list(states)

    async def db_status(self):
        return self.states.pop(0) if len(self.states) > 1 else self.states[0]


class Clair(ClairScanner):
    def __init__(self, ops_seq, healthy=True):
        self.ops_seq, self._healthy = list(ops_seq), healthy

    async def healthy(self):
        return (True, None) if self._healthy else (False, "clair unreachable: refused")

    async def update_operations(self):
        return self.ops_seq.pop(0) if len(self.ops_seq) > 1 else self.ops_seq[0]


def make(grype, clair, timeout=60):
    s = Settings(scanner_ready_timeout_seconds=timeout)
    return worker_mod.Worker(s, None, scanners={"grype": grype, "clair": clair}, inventory_fn=lambda e: None,
                             mirror=object())


async def test_reasons():
    w = make(Grype([{"valid": False, "error": "database does not exist"}]), Clair([{"osv/pub": []}]))
    reasons = await w.scanners_not_ready(["grype", "clair"])
    assert reasons[0].startswith("grype: vulnerability DB not ready (database does not exist)")
    assert "alpine, debian, ubuntu" in reasons[1]
    ready = make(Grype([{"valid": True}]), Clair([{"alpine-3.20-updater": [], "debian/updater/bookworm": [],
                                                    "ubuntu/updater/noble": []}]))
    assert await ready.scanners_not_ready(["grype", "clair"]) == []
    assert await make(Grype([{"valid": False}]), Clair([{}], healthy=False)).scanners_not_ready([]) == []
    assert "unreachable" in (await make(Grype([{"valid": True}]), Clair([{}], False)).scanners_not_ready(["clair"]))[0]


async def test_wait_until_ready(monkeypatch):
    sleeps = []

    async def fake_sleep(n):
        sleeps.append(n)

    monkeypatch.setattr(worker_mod.asyncio, "sleep", fake_sleep)
    w = make(Grype([{"valid": False}, {"valid": False}, {"valid": True}]),
             Clair([{"alpine": [], "debian": [], "ubuntu": []}]))
    ctx = worker_mod.ScanContext(1, AppSettings(), ["grype", "clair"])
    await w._wait_scanners_ready(ctx, ["grype", "clair"])
    assert len(sleeps) == 2
    assert any("waiting: grype" in line for line in ctx.log_lines) and ctx.log_lines[-1].endswith("scanners ready")


async def test_wait_times_out(monkeypatch):
    async def fake_sleep(n):
        return None

    monkeypatch.setattr(worker_mod.asyncio, "sleep", fake_sleep)
    w = make(Grype([{"valid": False}]), Clair([{}]), timeout=0)
    ctx = worker_mod.ScanContext(1, AppSettings(), ["grype"])
    await w._wait_scanners_ready(ctx, ["grype"])
    assert "scanner readiness timeout" in ctx.log_lines[-1]
