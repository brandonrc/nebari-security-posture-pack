"""Grype adapter: runs locally in the worker against a PVC-cached DB."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any

from ..severity import normalize_severity
import tempfile

from ..images import safe_ref_arg
from .base import (RAW_MAX_GZ_BYTES, Finding, ScanResult, Scanner, extract_cve, first_float, first_json_item,
                   iter_json_items, pack_raw_file, parse_time, run_proc, scratch_dir, tail)

NAME = "grype"


def _cvss(vuln: dict[str, Any]) -> float | None:
    best_primary = None
    scores = []
    for c in vuln.get("cvss") or []:
        s = first_float(((c.get("metrics") or {}).get("baseScore")))
        if s:
            scores.append(s)
            if c.get("type") == "Primary" and best_primary is None:
                best_primary = s
    return best_primary or (max(scores) if scores else None)


def grype_finding(m: dict[str, Any]) -> Finding | None:
    vuln = m.get("vulnerability") or {}
    art = m.get("artifact") or {}
    related = m.get("relatedVulnerabilities") or []
    vid = vuln.get("id") or ""
    if not vid:
        return None
    cve = extract_cve(vid) or next((extract_cve(r.get("id")) for r in related if extract_cve(r.get("id"))), None)
    fix = vuln.get("fix") or {}
    fixed = None
    if fix.get("state") == "fixed" and fix.get("versions"):
        fixed = ", ".join(fix["versions"])
    title = None
    for r in [vuln, *related]:
        if r.get("description"):
            title = r["description"].strip().splitlines()[0][:200]
            break
    cvss = _cvss(vuln) or next((_cvss(r) for r in related if _cvss(r)), None)
    url = vuln.get("dataSource") or next(iter(vuln.get("urls") or []), None)
    return Finding(
        vuln_id=cve or vid,
        severity=normalize_severity(vuln.get("severity")),
        package=art.get("name") or "",
        installed_version=art.get("version"),
        fixed_version=fixed,
        pkg_type=art.get("type"),
        scanner=NAME,
        cvss=cvss,
        title=title,
        url=url,
    )


def grype_meta(descriptor: dict[str, Any] | None, distro: dict[str, Any] | None) -> dict[str, Any]:
    descriptor, distro = descriptor or {}, distro or {}
    meta: dict[str, Any] = {"version": descriptor.get("version")}
    if distro.get("name"):
        meta["os_family"] = distro.get("name")
        meta["os_name"] = distro.get("version")
    db = descriptor.get("db") or {}
    built = db.get("built") or (db.get("status") or {}).get("built")
    if built:
        meta["db_built"] = parse_time(built)
    return meta


def vex_ignored(m: dict[str, Any]) -> bool:
    """An `ignoredMatches` entry grype dropped because of a `--vex` statement (not a user ignore
    rule): it is returned as a finding, and posture.vex decides (authoritative, all scanners)."""
    return any(isinstance(r, dict) and (r.get("vex-status") or r.get("namespace") == "vex")
               for r in m.get("appliedIgnoreRules") or [])


def parse_grype_json(doc: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    matches = list(doc.get("matches") or []) + [m for m in doc.get("ignoredMatches") or [] if vex_ignored(m)]
    findings = [f for m in matches if (f := grype_finding(m)) is not None]
    return findings, grype_meta(doc.get("descriptor"), doc.get("distro"))


def parse_grype_file(path: str) -> tuple[list[Finding], dict[str, Any]]:
    """Streaming parse (ijson): the matches are read one by one, the document never sits in memory."""
    findings = [f for m in iter_json_items(path, "matches.item") if (f := grype_finding(m)) is not None]
    findings += [f for m in iter_json_items(path, "ignoredMatches.item")
                 if vex_ignored(m) and (f := grype_finding(m)) is not None]
    return findings, grype_meta(first_json_item(path, "descriptor"), first_json_item(path, "distro"))


def _source_arg(ref: str) -> str:
    """`registry:<ref>` (never a local docker daemon) or `oci-dir:<abs path>` (MIRROR_MODE=local)."""
    if ref.startswith("oci-dir:"):
        path = ref[len("oci-dir:"):]
        if not path.startswith("/") or ".." in path.split("/") or not os.path.isdir(path):
            raise ValueError(f"refusing OCI layout path: {path[:80]!r}")
        return ref
    return "registry:" + safe_ref_arg(ref[len("registry:"):] if ref.startswith("registry:") else ref)


class GrypeScanner(Scanner):
    name = NAME

    def __init__(self, binary: str = "grype", cache_dir: str = "/cache", docker_config: str | None = None,
                 max_concurrent: int = 2, raw_max_gz: int = RAW_MAX_GZ_BYTES):
        self.binary = binary
        self.db_dir = os.path.join(cache_dir, "grype")
        self.scratch = cache_dir
        self.docker_config = docker_config
        # grype dominates worker memory (up to ~3.2 GiB per process measured): cap concurrent runs
        # independently of scan parallelism (GRYPE_MAX_CONCURRENT, architecture review M2)
        self.max_concurrent = max(1, int(max_concurrent))
        self._sem: asyncio.Semaphore | None = None
        self.raw_max_gz = raw_max_gz
        self.running = 0  # grype processes alive right now (tests / metrics)

    @property
    def semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.max_concurrent)
        return self._sem

    def env(self, insecure: bool = False) -> dict[str, str]:
        env = {
            "GRYPE_DB_CACHE_DIR": self.db_dir,
            "GRYPE_DB_AUTO_UPDATE": "false",
            "GRYPE_DB_VALIDATE_AGE": "false",
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        }
        # set explicitly both ways: the chart may export GRYPE_REGISTRY_INSECURE_USE_HTTP globally
        flag = "true" if insecure else "false"
        env["GRYPE_REGISTRY_INSECURE_USE_HTTP"] = flag
        env["GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = flag
        if self.docker_config:
            env["DOCKER_CONFIG"] = self.docker_config
        return env

    async def version(self) -> str | None:
        res = await run_proc([self.binary, "version", "-o", "json"], 30, self.env())
        try:
            return json.loads(res.stdout).get("version")
        except (json.JSONDecodeError, AttributeError):
            return None

    async def db_status(self) -> dict[str, Any]:
        res = await run_proc([self.binary, "db", "status", "-o", "json"], 60, self.env())
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return {"valid": False, "error": tail(res.stderr or res.stdout)}

    async def db_updated_at(self) -> datetime | None:
        st = await self.db_status()
        return parse_time(st.get("built"))

    async def update_db(self, timeout: float = 1800) -> tuple[bool, str | None]:
        os.makedirs(self.db_dir, exist_ok=True)
        res = await run_proc([self.binary, "db", "update"], timeout, self.env())
        if res.timed_out:
            return False, "grype db update timed out"
        if res.returncode != 0:
            return False, tail(res.stderr or res.stdout)
        return True, None

    def argv(self, source: str) -> list[str]:
        argv = [self.binary, "-o", "json"]
        if self.vex_files and source.startswith("registry:"):  # never for oci-dir: (no product to match)
            for f in self.vex_files:
                argv += ["--vex", f]
        return argv + ["--", source]

    async def scan(self, ref: str, *, insecure: bool = False, timeout: float = 600) -> ScanResult:
        try:
            source = _source_arg(ref)
        except ValueError as e:
            return ScanResult(NAME, "error", error=str(e))
        with tempfile.TemporaryDirectory(dir=scratch_dir(self.scratch)) as d:
            out = os.path.join(d, "grype.json")
            async with self.semaphore:  # the timeout starts once a slot is free
                self.running += 1
                try:
                    res = await run_proc(self.argv(source), timeout, self.env(insecure), stdout_file=out)
                finally:
                    self.running -= 1
            if res.timed_out:
                return ScanResult(NAME, "timeout", error=f"timed out after {int(timeout)}s",
                                  duration_ms=res.duration_ms)
            if res.returncode != 0:
                err = tail(res.stderr) or f"exit {res.returncode}"
                status = "unsupported" if "unable to detect" in err.lower() else "error"
                return ScanResult(NAME, status, error=err, duration_ms=res.duration_ms)
            if res.truncated:
                return ScanResult(NAME, "error", error="grype output exceeded the size cap",
                                  duration_ms=res.duration_ms)
            try:
                findings, meta = await asyncio.to_thread(parse_grype_file, out)
            except Exception as e:  # noqa: BLE001  (ijson.JSONError, UnicodeDecodeError)
                gz, size, cut = await asyncio.to_thread(pack_raw_file, out, NAME, self.raw_max_gz)
                return ScanResult(NAME, "error", error=f"invalid JSON from grype: {e}", duration_ms=res.duration_ms,
                                  raw_gz=gz, raw_size=size, raw_truncated=cut)
            summary_meta = {k: v for k, v in meta.items() if k != "db_built"}
            gz, size, cut = await asyncio.to_thread(pack_raw_file, out, NAME, self.raw_max_gz, len(findings),
                                                    summary_meta)
        return ScanResult(NAME, "ok", version=meta.get("version"), db_updated_at=meta.get("db_built"),
                          findings=findings, duration_ms=res.duration_ms, raw_gz=gz, raw_size=size,
                          raw_truncated=cut, os_family=meta.get("os_family"), os_name=meta.get("os_name"))
