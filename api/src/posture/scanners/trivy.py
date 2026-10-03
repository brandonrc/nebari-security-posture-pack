"""Trivy adapter: `trivy image --server` against the in-cluster trivy server."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any

import httpx

from ..severity import normalize_severity
import tempfile

from ..images import safe_ref_arg
from .base import (RAW_MAX_GZ_BYTES, Finding, ScanResult, Scanner, extract_cve, first_float, first_json_item,
                   iter_json_items, pack_raw_file, parse_time, run_proc, scratch_dir, tail)

NAME = "trivy"


def trivy_findings(result: dict[str, Any]) -> list[Finding]:
    """Findings of one entry of trivy's top-level `Results`."""
    findings: list[Finding] = []
    rtype = result.get("Type") or result.get("Class")
    for v in result.get("Vulnerabilities") or []:
        vid = v.get("VulnerabilityID") or ""
        if not vid:
            continue
        scores: list[float] = []
        for src in (v.get("CVSS") or {}).values():
            if isinstance(src, dict):
                s = first_float(src.get("V3Score"), src.get("V40Score"), src.get("V2Score"))
                if s:
                    scores.append(s)
        nvd = (v.get("CVSS") or {}).get("nvd") or {}
        cvss = first_float(nvd.get("V3Score"), nvd.get("V40Score")) or (max(scores) if scores else None)
        findings.append(
            Finding(
                vuln_id=extract_cve(vid) or vid,
                severity=normalize_severity(v.get("Severity")),
                package=v.get("PkgName") or "",
                installed_version=v.get("InstalledVersion"),
                fixed_version=(v.get("FixedVersion") or None),
                pkg_type=rtype,
                scanner=NAME,
                cvss=cvss,
                title=v.get("Title") or (v.get("Description") or "")[:200] or None,
                url=v.get("PrimaryURL") or None,
            )
        )
    return findings


def trivy_meta(os_: dict[str, Any] | None, version: str | None) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if os_:
        meta["os_family"] = os_.get("Family")
        meta["os_name"] = os_.get("Name")
    meta["version"] = version
    return meta


def parse_trivy_json(doc: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    """Parse `trivy image --format json` output -> findings + metadata."""
    findings = [f for result in doc.get("Results") or [] for f in trivy_findings(result)]
    return findings, trivy_meta((doc.get("Metadata") or {}).get("OS"), (doc.get("Trivy") or {}).get("Version"))


def parse_trivy_file(path: str) -> tuple[list[Finding], dict[str, Any]]:
    """Streaming parse (ijson): one `Results` entry in memory at a time."""
    findings = [f for result in iter_json_items(path, "Results.item") for f in trivy_findings(result)]
    return findings, trivy_meta(first_json_item(path, "Metadata.OS"), first_json_item(path, "Trivy.Version"))


class TrivyScanner(Scanner):
    name = NAME

    def __init__(self, server_url: str, binary: str = "trivy", cache_dir: str = "/cache",
                 docker_config: str | None = None, raw_max_gz: int = RAW_MAX_GZ_BYTES):
        self.raw_max_gz = raw_max_gz
        self.server_url = server_url.rstrip("/")
        self.binary = binary
        self.cache_dir = os.path.join(cache_dir, "trivy-client")
        self.scratch = cache_dir
        self.docker_config = docker_config
        self._meta: dict[str, Any] | None = None

    async def _server_meta(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{self.server_url}/version")
            r.raise_for_status()
            return r.json()

    async def version(self) -> str | None:
        try:
            self._meta = await self._server_meta()
            return self._meta.get("Version")
        except Exception:
            res = await run_proc([self.binary, "--version"], 30)
            out = res.stdout.strip()
            return out.split()[-1] if out else None

    async def db_updated_at(self) -> datetime | None:
        try:
            meta = self._meta or await self._server_meta()
            return parse_time((meta.get("VulnerabilityDB") or {}).get("UpdatedAt"))
        except Exception:
            return None

    async def healthy(self) -> tuple[bool, str | None]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.server_url}/healthz")
                return r.status_code == 200, None if r.status_code == 200 else f"healthz {r.status_code}"
        except Exception as e:  # noqa: BLE001
            return False, f"trivy server unreachable: {e}"

    def argv(self, ref: str, insecure: bool, timeout: float) -> list[str]:
        argv = [self.binary, "image", "--server", self.server_url, "--format", "json",
                "--scanners", "vuln", "--quiet", "--cache-dir", self.cache_dir,
                "--timeout", f"{int(timeout)}s"]
        if insecure:
            argv.append("--insecure")
        if ref.startswith("oci-dir:"):  # MIRROR_MODE=local: per-digest OCI layout on the cache volume
            path = ref[len("oci-dir:"):]
            if not path.startswith("/") or ".." in path.split("/"):
                raise ValueError(f"refusing OCI layout path: {path[:80]!r}")
            argv += ["--input", path]
            return argv
        argv += ["--", safe_ref_arg(ref)]
        return argv

    async def scan(self, ref: str, *, insecure: bool = False, timeout: float = 600) -> ScanResult:
        env = {"TRIVY_NO_PROGRESS": "true", "TRIVY_DISABLE_VEX_NOTICE": "true",
               "TRIVY_INSECURE": "true" if insecure else "false"}
        if self.docker_config:
            env["DOCKER_CONFIG"] = self.docker_config
        try:
            argv = self.argv(ref, insecure, timeout - 5 if timeout > 10 else timeout)
        except ValueError as e:
            return ScanResult(NAME, "error", error=str(e))
        with tempfile.TemporaryDirectory(dir=scratch_dir(self.scratch)) as d:
            out = os.path.join(d, "trivy.json")
            res = await run_proc(argv, timeout, env, stdout_file=out)
            if res.timed_out:
                return ScanResult(NAME, "timeout", error=f"timed out after {int(timeout)}s",
                                  duration_ms=res.duration_ms)
            if res.returncode != 0:
                return ScanResult(NAME, "error", error=tail(res.stderr) or f"exit {res.returncode}",
                                  duration_ms=res.duration_ms)
            if res.truncated:
                return ScanResult(NAME, "error", error="trivy output exceeded the size cap",
                                  duration_ms=res.duration_ms)
            try:
                findings, meta = await asyncio.to_thread(parse_trivy_file, out)
            except Exception as e:  # noqa: BLE001  (ijson.JSONError, UnicodeDecodeError)
                gz, size, cut = await asyncio.to_thread(pack_raw_file, out, NAME, self.raw_max_gz)
                return ScanResult(NAME, "error", error=f"invalid JSON from trivy: {e}", duration_ms=res.duration_ms,
                                  raw_gz=gz, raw_size=size, raw_truncated=cut)
            gz, size, cut = await asyncio.to_thread(pack_raw_file, out, NAME, self.raw_max_gz, len(findings), meta)
        return ScanResult(NAME, "ok", version=meta.get("version"), findings=findings,
                          duration_ms=res.duration_ms, raw_gz=gz, raw_size=size, raw_truncated=cut,
                          os_family=meta.get("os_family"), os_name=meta.get("os_name"))
