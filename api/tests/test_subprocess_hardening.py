"""Security review M2/M3: image-ref grammar, `--`, env allowlist, bounded capture, group kill."""

from __future__ import annotations

import asyncio
import os
import stat
import time

import pytest

from posture.images import parse_image_ref, safe_ref_arg
from posture.scanners import base
from posture.scanners.base import run_proc, subprocess_env
from posture.scanners.clair import ClairScanner
from posture.scanners.grype import GrypeScanner
from posture.scanners.trivy import TrivyScanner


def fake_bin(tmp_path, name, script):
    (tmp_path / "bin").mkdir(exist_ok=True)
    p = tmp_path / "bin" / name
    p.write_text("#!/bin/sh\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


# ------------------------------------------------------------------ image reference grammar (M2)
@pytest.mark.parametrize("bad", [
    "--server=evil.example/x", "a.b/x:--help", "-x", "alpine:1 --x", "alpine\n:1", "evil host.io/a:1",
    "a.b/x:-tag", "re_g.io/a:1", "a.b/x:" + "t" * 129, "-registry.io/a:1",
])
def test_parse_rejects_argument_injection(bad):
    with pytest.raises(ValueError):
        parse_image_ref(bad)


@pytest.mark.parametrize("good", ["[::1]:5000/a:b", "my-reg.io:443/a/b_c__d:v1.2-rc_3", "alpine"])
def test_parse_accepts_grammar(good):
    parse_image_ref(good)


@pytest.mark.parametrize("bad", ["-x", "--server=x", "a b", "a\tb", "", "a;b", "$(x)"])
def test_safe_ref_arg(bad):
    with pytest.raises(ValueError):
        safe_ref_arg(bad)


async def test_scanners_refuse_unsafe_refs_and_pass_double_dash(tmp_path):
    out = tmp_path / "args"
    t = fake_bin(tmp_path, "trivy", f'echo "$@" > {out}\necho {{}}\n')
    r = await TrivyScanner("http://t", t, str(tmp_path)).scan("--server=evil", timeout=5)
    assert r.status == "error" and "unsafe" in r.error and not out.exists()
    r = await TrivyScanner("http://t", t, str(tmp_path)).scan("reg.io/a:1", timeout=5)
    assert out.read_text().split()[-2:] == ["--", "reg.io/a:1"]
    g = fake_bin(tmp_path, "grype", "echo '{}'\n")
    assert (await GrypeScanner(g, str(tmp_path)).scan("-o", timeout=5)).status == "error"
    c = fake_bin(tmp_path, "clairctl", "echo '{}'\n")
    assert (await ClairScanner("http://c", c, str(tmp_path)).scan("-h", timeout=5)).status == "error"


# ------------------------------------------------------------------ env allowlist (M3)
def test_subprocess_env_allowlist(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:pw@db/x")
    monkeypatch.setenv("DB_PASSWORD", "pw")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "s")
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "s")
    monkeypatch.setenv("PROVENANCE_COMPAT_TOKEN", "t")
    monkeypatch.setenv("TRIVY_PASSWORD", "registry-pw")
    monkeypatch.setenv("RANDOM_APP_SETTING", "x")
    monkeypatch.setenv("TRIVY_TIMEOUT", "5m")
    monkeypatch.setenv("DOCKER_CONFIG", "/etc/docker")
    env = subprocess_env({"EXTRA": "1"})
    for k in ("DATABASE_URL", "DB_PASSWORD", "OIDC_CLIENT_SECRET", "KEYCLOAK_CLIENT_SECRET",
              "PROVENANCE_COMPAT_TOKEN", "TRIVY_PASSWORD", "RANDOM_APP_SETTING"):
        assert k not in env
    assert env["TRIVY_TIMEOUT"] == "5m" and env["DOCKER_CONFIG"] == "/etc/docker" and env["EXTRA"] == "1"
    assert "PATH" in env


async def test_child_does_not_see_db_password(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "hunter2")
    monkeypatch.setenv("DATABASE_URL", "postgresql://posture:hunter2@db/posture")
    res = await run_proc(["sh", "-c", "env"], 5)
    assert "hunter2" not in res.stdout


async def test_stdin_is_devnull():
    res = await run_proc(["sh", "-c", "cat; echo done"], 5)
    assert res.stdout.strip() == "done"


# ------------------------------------------------------------------ bounded capture (M3)
async def test_stdout_to_file_is_capped(tmp_path):
    out = tmp_path / "o"
    res = await run_proc(["sh", "-c", "head -c 300000 /dev/zero"], 10, stdout_file=str(out), stdout_max=100_000)
    assert res.returncode == 0 and res.truncated and out.stat().st_size == 100_000 and res.stdout == ""


async def test_memory_capture_and_stderr_tail_are_capped(monkeypatch):
    monkeypatch.setattr(base, "STDERR_MAX_BYTES", 1000)
    res = await run_proc(["sh", "-c", "head -c 50000 /dev/zero; head -c 5000 /dev/zero | tr '\\0' e >&2; "
                                      "printf END >&2"], 10, stdout_max=1000)
    assert len(res.stdout) == 1000 and res.truncated
    assert len(res.stderr) == 1000 and res.stderr.endswith("END")


# ------------------------------------------------------------------ process-group kill, cancellation (M3)
def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # zombies count as dead
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


async def test_timeout_kills_process_group(tmp_path):
    pidfile = tmp_path / "pid"
    start = time.monotonic()
    res = await run_proc(["sh", "-c", f"sleep 30 & echo $! > {pidfile}; wait"], 1.5)
    assert res.timed_out and time.monotonic() - start < 6
    assert not _alive(int(pidfile.read_text()))  # the grandchild died with the group


async def test_sigterm_ignored_escalates_to_sigkill(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "KILL_GRACE_SECONDS", 0.5)
    start = time.monotonic()
    res = await run_proc(["sh", "-c", "trap '' TERM; sleep 30 & wait; sleep 30"], 0.3)
    assert res.timed_out and time.monotonic() - start < 4


async def test_cancel_kills_children_promptly(tmp_path):
    pidfile = tmp_path / "pid"
    task = asyncio.create_task(run_proc(["sh", "-c", f"sleep 60 & echo $! > {pidfile}; wait"], 600))
    for _ in range(50):
        await asyncio.sleep(0.05)
        if pidfile.exists() and pidfile.read_text().strip():
            break
    start = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - start < 3
    assert not _alive(int(pidfile.read_text()))


async def test_cancelled_scan_kills_scanner(tmp_path):
    pidfile = tmp_path / "pid"
    slow = fake_bin(tmp_path, "trivy", f"sleep 60 & echo $! > {pidfile}\nwait\n")
    task = asyncio.create_task(TrivyScanner("http://t", slow, str(tmp_path)).scan("reg.io/a:1", timeout=600))
    for _ in range(50):
        await asyncio.sleep(0.05)
        if pidfile.exists() and pidfile.read_text().strip():
            break
    start = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - start < 3 and not _alive(int(pidfile.read_text()))
