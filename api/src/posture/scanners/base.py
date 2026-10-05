"""Common scanner adapter types and subprocess helper."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import tempfile
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
    # raw output already packed by the adapter (pack_raw_file): gzip bytes, uncompressed size and
    # whether the findings payload was dropped for size (the stored document is still valid JSON)
    raw_gz: bytes | None = None
    raw_size: int = 0
    raw_truncated: bool = False

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
    stdout_path: str | None = None  # set when the caller asked for stdout in a file
    truncated: bool = False  # stdout or stderr exceeded its cap (the excess was discarded)


# ---------------------------------------------------------------- subprocess hardening (security M2/M3)
# Only these variables reach scanner / skopeo / cosign subprocesses, which parse untrusted
# registry content. DATABASE_URL, DB_PASSWORD, OIDC_*, KEYCLOAK_* and similar never do.
ENV_ALLOW = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "USER",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "DOCKER_CONFIG", "REGISTRY_AUTH_FILE", "XDG_RUNTIME_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "TUF_ROOT", "GOMEMLIMIT", "GOMAXPROCS",
})
ENV_ALLOW_PREFIXES = ("TRIVY_", "GRYPE_", "COSIGN_", "SIGSTORE_")
_ENV_DENY_RE = re.compile(r"PASSWORD|SECRET|PRIVATE_KEY|DATABASE_URL|^OIDC_|^KEYCLOAK_|^PROVENANCE_COMPAT_TOKEN",
                          re.IGNORECASE)
STDOUT_MAX_BYTES = 256 * 1024 * 1024  # file-backed stdout (scanner JSON)
MEM_STDOUT_MAX_BYTES = 4 * 1024 * 1024  # in-memory stdout (version / status commands)
STDERR_MAX_BYTES = 256 * 1024  # stderr keeps the tail only
KILL_GRACE_SECONDS = 10.0  # SIGTERM -> SIGKILL


def subprocess_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal allowlisted environment for a child process plus `extra` (caller-chosen)."""
    env = {k: v for k, v in os.environ.items()
           if (k in ENV_ALLOW or k.startswith(ENV_ALLOW_PREFIXES)) and not _ENV_DENY_RE.search(k)}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    if extra:
        env.update(extra)
    return env


def _signal_group(proc: asyncio.subprocess.Process, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)  # start_new_session=True: pgid == pid
    except (ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass


async def terminate_group(proc: asyncio.subprocess.Process, grace: float | None = None) -> None:
    """SIGTERM the whole process group, SIGKILL after `grace` seconds; always reaps."""
    grace = KILL_GRACE_SECONDS if grace is None else grace
    if proc.returncode is None:
        _signal_group(proc, signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), grace)
        except (TimeoutError, asyncio.TimeoutError):
            pass
    _signal_group(proc, signal.SIGKILL)  # stragglers in the group (grandchildren) too
    await proc.wait()


async def _drain(stream: asyncio.StreamReader, sink: Any, cap: int, keep_tail: bool) -> bool:
    """Copy `stream` into `sink` (file or bytearray) up to `cap` bytes; returns True when capped.
    Keeps draining past the cap so the child never blocks on a full pipe."""
    written = 0
    capped = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return capped
        if keep_tail:  # bytearray sink: keep the last `cap` bytes
            sink.extend(chunk)
            if len(sink) > cap:
                del sink[: len(sink) - cap]
                capped = True
            continue
        room = cap - written
        if room <= 0:
            capped = True
            continue
        part = chunk[:room]
        if isinstance(sink, bytearray):
            sink.extend(part)
        else:
            sink.write(part)
        written += len(part)
        if len(chunk) > room:
            capped = True


async def run_proc(argv: list[str], timeout: float, env: dict[str, str] | None = None, *,
                   stdout_file: str | None = None, stdout_max: int | None = None) -> ProcResult:
    """Run a subprocess safely: allowlisted env (`env` is added on top), stdin=/dev/null, own
    process group, bounded capture, hard timeout and cancellation that kill the whole group
    (SIGTERM, then SIGKILL after KILL_GRACE_SECONDS).

    With `stdout_file`, stdout is streamed to that file (capped at `stdout_max`, default
    STDOUT_MAX_BYTES) and `ProcResult.stdout` is empty: parse the file. Otherwise stdout is kept
    in memory up to MEM_STDOUT_MAX_BYTES. stderr keeps its last STDERR_MAX_BYTES."""
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            env=subprocess_env(env),
            start_new_session=True,
        )
    except FileNotFoundError:
        return ProcResult(None, "", f"executable not found: {argv[0]}", False, 0)
    err_buf = bytearray()
    out_buf = bytearray()
    out_fh = open(stdout_file, "wb") if stdout_file else None  # noqa: SIM115
    timed_out = False
    try:
        out_task = asyncio.ensure_future(_drain(proc.stdout, out_fh if out_fh else out_buf,
                                                (stdout_max or STDOUT_MAX_BYTES) if out_fh
                                                else (stdout_max or MEM_STDOUT_MAX_BYTES), False))
        err_task = asyncio.ensure_future(_drain(proc.stderr, err_buf, STDERR_MAX_BYTES, True))
        readers = asyncio.gather(out_task, err_task)
        try:
            capped = await asyncio.wait_for(asyncio.shield(_wait_all(proc, readers)), timeout=timeout)
        except (TimeoutError, asyncio.TimeoutError):
            timed_out = True
            await terminate_group(proc)
            capped = await _finish_readers(readers)
        except asyncio.CancelledError:
            await terminate_group(proc)
            await _finish_readers(readers)
            raise
    finally:
        if out_fh:
            out_fh.close()
    return ProcResult(
        proc.returncode,
        out_buf.decode("utf-8", "replace"),
        err_buf.decode("utf-8", "replace"),
        timed_out,
        int((time.monotonic() - start) * 1000),
        stdout_path=stdout_file,
        truncated=any(capped),
    )


async def _wait_all(proc: asyncio.subprocess.Process, readers: asyncio.Future) -> tuple[bool, bool]:
    capped = await readers
    await proc.wait()
    return capped


async def _finish_readers(readers: asyncio.Future) -> tuple[bool, bool]:
    try:
        return await asyncio.wait_for(asyncio.shield(readers), 5)
    except (TimeoutError, asyncio.TimeoutError):
        readers.cancel()
        return (True, True)
    except Exception:  # noqa: BLE001
        return (True, True)


def scratch_dir(cache_dir: str) -> str:
    """Directory for subprocess output files: on the cache volume (not the tmpfs), so large
    scanner JSON neither lives in memory nor fills /tmp."""
    d = os.path.join(cache_dir, "tmp")
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except OSError:
        return tempfile.gettempdir()


# ---------------------------------------------------------------- raw output (architecture M2 / M6)
RAW_MAX_GZ_BYTES = 4 * 1024 * 1024  # default for RAW_MAX_GZ_BYTES (settings.raw_max_gz_bytes)


def raw_summary(scanner: str, raw_size: int, max_gz: int, findings: int | None = None,
                meta: dict[str, Any] | None = None) -> bytes:
    """Stand-in stored instead of an oversized raw document: valid JSON, findings payload dropped."""
    import json

    doc: dict[str, Any] = {"truncated": True, "scanner": scanner, "rawSize": raw_size, "maxGzipBytes": max_gz,
                           "reason": "raw scanner output exceeded the stored size limit; the findings payload was "
                                     "dropped (normalized findings are in the database)"}
    if findings is not None:
        doc["findingsCount"] = findings
    if meta:
        doc["metadata"] = meta
    return json.dumps(doc).encode()


def pack_raw_file(path: str, scanner: str, max_gz: int = RAW_MAX_GZ_BYTES, findings: int | None = None,
                  meta: dict[str, Any] | None = None) -> tuple[bytes, int, bool]:
    """Gzip a raw output file in chunks -> (gz bytes, uncompressed size, truncated). Never cuts a
    document in the middle: past `max_gz` compressed bytes it stores `raw_summary` instead."""
    import gzip
    import io

    size = os.path.getsize(path)
    buf = io.BytesIO()
    over = False
    with open(path, "rb") as src, gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        while chunk := src.read(1 << 20):
            gz.write(chunk)
            if buf.tell() > max_gz:
                over = True
                break
    if over or len(buf.getvalue()) > max_gz:
        return gzip.compress(raw_summary(scanner, size, max_gz, findings, meta)), size, True
    return buf.getvalue(), size, False


def pack_raw_text(text: str, scanner: str, max_gz: int = RAW_MAX_GZ_BYTES, findings: int | None = None,
                  meta: dict[str, Any] | None = None) -> tuple[bytes, int, bool]:
    import gzip

    data = text.encode("utf-8", "replace")
    gz = gzip.compress(data, compresslevel=6)
    if len(gz) > max_gz:
        return gzip.compress(raw_summary(scanner, len(data), max_gz, findings, meta)), len(data), True
    return gz, len(data), False


def iter_json_items(path: str, prefix: str):
    """Stream the items at `prefix` (ijson syntax, e.g. `matches.item`) without loading the file."""
    import ijson

    with open(path, "rb") as fh:
        yield from ijson.items(fh, prefix, use_float=True)


def first_json_item(path: str, prefix: str) -> Any:
    for item in iter_json_items(path, prefix):
        return item
    return None


def read_capped(path: str, limit: int = RAW_MAX_BYTES + 1) -> str:
    """First `limit` bytes of a file as text (raw scanner output for the DB)."""
    with open(path, "rb") as fh:
        return fh.read(limit).decode("utf-8", "replace")


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
    # OpenVEX documents handed to the scanner (`--vex`) when it scans by image reference; set by
    # the worker from posture.vex.VexStore. Never used for oci-dir: paths (no product to match).
    vex_files: tuple[str, ...] = ()

    async def scan(self, ref: str, *, insecure: bool = False, timeout: float = 600) -> ScanResult:  # pragma: no cover
        raise NotImplementedError

    async def version(self) -> str | None:  # pragma: no cover
        raise NotImplementedError

    async def db_updated_at(self) -> datetime | None:  # pragma: no cover
        raise NotImplementedError
