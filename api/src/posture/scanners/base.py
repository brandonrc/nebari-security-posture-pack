"""Common scanner adapter types and subprocess helper."""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..logs import get_logger

log = get_logger(__name__)

RAW_MAX_BYTES = 2 * 1024 * 1024
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class Finding:
    vuln_id: str
    severity: str
    package: str
    installed_version: str | None
    fixed_version: str | None
    pkg_type: str | None
    scanner: str
    cvss: float | None = None
    title: str | None = None
    url: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "vulnId": self.vuln_id,
            "severity": self.severity,
            "package": self.package,
            "installedVersion": self.installed_version,
            "fixedVersion": self.fixed_version,
            "pkgType": self.pkg_type,
            "cvss": self.cvss,
            "title": self.title,
            "url": self.url,
            "scanner": self.scanner,
        }


@dataclass
class ScanResult:
    scanner: str
    status: str  # ok | error | timeout | unsupported
    version: str | None = None
    db_updated_at: datetime | None = None
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)
    duration_ms: int = 0
    raw: str | None = None
    os_family: str | None = None
    os_name: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass
class ProcResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


async def run_proc(argv: list[str], timeout: float, env: dict[str, str] | None = None) -> ProcResult:
    """Run a subprocess with a hard timeout (kills the process on expiry)."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            env=full_env,
        )
    except FileNotFoundError:
        return ProcResult(None, "", f"executable not found: {argv[0]}", False, 0)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        timed_out = False
    except (TimeoutError, asyncio.TimeoutError):
        proc.kill()
        out, err = await proc.communicate()
        timed_out = True
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    return ProcResult(
        proc.returncode,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
        timed_out,
        int((time.monotonic() - start) * 1000),
    )


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def tail(text: str, limit: int = 1500) -> str:
    text = _ANSI_RE.sub("", text or "").strip()
    return text if len(text) <= limit else "…" + text[-limit:]


def extract_cve(*candidates: str | None) -> str | None:
    for c in candidates:
        if c:
            m = _CVE_RE.search(c)
            if m:
                return m.group(0).upper()
    return None


def parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    # trim nanoseconds to microseconds
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(.*)$", v)
    if m:
        frac = (m.group(2) or "")[:7]
        v = m.group(1) + frac + m.group(3)
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        from datetime import UTC

        dt = dt.replace(tzinfo=UTC)
    return dt


def first_float(*values: Any) -> float | None:
    for v in values:
        try:
            if v is not None and v != "":
                f = float(v)
                if f > 0:
                    return f
        except (TypeError, ValueError):
            continue
    return None


class Scanner:
    """Adapter interface. Subclasses implement `scan`, `version`, `db_updated_at`."""

    name: str = "base"

    async def scan(self, ref: str, *, insecure: bool = False, timeout: float = 600) -> ScanResult:  # pragma: no cover
        raise NotImplementedError

    async def version(self) -> str | None:  # pragma: no cover
        raise NotImplementedError

    async def db_updated_at(self) -> datetime | None:  # pragma: no cover
        raise NotImplementedError
