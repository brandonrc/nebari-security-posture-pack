"""Trivy adapter: `trivy image --server` against the in-cluster trivy server."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

import httpx

from ..severity import normalize_severity
from .base import Finding, ScanResult, Scanner, extract_cve, first_float, parse_time, run_proc, tail

NAME = "trivy"


def parse_trivy_json(doc: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    """Parse `trivy image --format json` output -> findings + metadata."""
    findings: list[Finding] = []
    for result in doc.get("Results") or []:
        rtype = result.get("Type") or result.get("Class")
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            if not vid:
                continue
            cvss = None
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
    meta: dict[str, Any] = {}
    os_ = (doc.get("Metadata") or {}).get("OS") or {}
    if os_:
        meta["os_family"] = os_.get("Family")
        meta["os_name"] = os_.get("Name")
    meta["version"] = (doc.get("Trivy") or {}).get("Version")
    return findings, meta


class TrivyScanner(Scanner):
    name = NAME

    def __init__(self, server_url: str, binary: str = "trivy", cache_dir: str = "/cache",
                 docker_config: str | None = None):
        self.server_url = server_url.rstrip("/")
        self.binary = binary
        self.cache_dir = os.path.join(cache_dir, "trivy-client")
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
        argv.append(ref)
        return argv

    async def scan(self, ref: str, *, insecure: bool = False, timeout: float = 600) -> ScanResult:
        env = {"TRIVY_NO_PROGRESS": "true", "TRIVY_DISABLE_VEX_NOTICE": "true",
               "TRIVY_INSECURE": "true" if insecure else "false"}
        if self.docker_config:
            env["DOCKER_CONFIG"] = self.docker_config
        res = await run_proc(self.argv(ref, insecure, timeout - 5 if timeout > 10 else timeout), timeout, env)
        if res.timed_out:
            return ScanResult(NAME, "timeout", error=f"timed out after {int(timeout)}s", duration_ms=res.duration_ms)
        if res.returncode != 0:
            return ScanResult(NAME, "error", error=tail(res.stderr or res.stdout) or f"exit {res.returncode}",
                              duration_ms=res.duration_ms)
        try:
            doc = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            return ScanResult(NAME, "error", error=f"invalid JSON from trivy: {e}", duration_ms=res.duration_ms,
                              raw=res.stdout)
        findings, meta = parse_trivy_json(doc)
        return ScanResult(NAME, "ok", version=meta.get("version"), findings=findings,
                          duration_ms=res.duration_ms, raw=res.stdout,
                          os_family=meta.get("os_family"), os_name=meta.get("os_name"))
