"""Grype adapter: runs locally in the worker against a PVC-cached DB."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from ..severity import normalize_severity
import tempfile

from ..images import safe_ref_arg
from .base import (Finding, ScanResult, Scanner, extract_cve, first_float, parse_time, read_capped, run_proc,
                   scratch_dir, tail)

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


def parse_grype_json(doc: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    for m in doc.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        vid = vuln.get("id") or ""
        if not vid:
            continue
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
        findings.append(
            Finding(
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
        )
    meta: dict[str, Any] = {"version": (doc.get("descriptor") or {}).get("version")}
    distro = doc.get("distro") or {}
    if distro.get("name"):
        meta["os_family"] = distro.get("name")
        meta["os_name"] = distro.get("version")
    db = (doc.get("descriptor") or {}).get("db") or {}
    built = db.get("built") or (db.get("status") or {}).get("built")
    if built:
        meta["db_built"] = parse_time(built)
    return findings, meta


class GrypeScanner(Scanner):
    name = NAME

    def __init__(self, binary: str = "grype", cache_dir: str = "/cache", docker_config: str | None = None):
        self.binary = binary
        self.db_dir = os.path.join(cache_dir, "grype")
        self.scratch = cache_dir
        self.docker_config = docker_config

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

    async def scan(self, ref: str, *, insecure: bool = False, timeout: float = 600) -> ScanResult:
        # force the registry source: never consult a local docker daemon
        try:
            source = "registry:" + safe_ref_arg(ref[len("registry:"):] if ref.startswith("registry:") else ref)
        except ValueError as e:
            return ScanResult(NAME, "error", error=str(e))
        with tempfile.TemporaryDirectory(dir=scratch_dir(self.scratch)) as d:
            out = os.path.join(d, "grype.json")
            res = await run_proc([self.binary, "-o", "json", "--", source], timeout, self.env(insecure),
                                 stdout_file=out)
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
                with open(out, "rb") as fh:
                    doc = json.load(fh)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return ScanResult(NAME, "error", error=f"invalid JSON from grype: {e}", duration_ms=res.duration_ms,
                                  raw=read_capped(out))
            raw = read_capped(out)
        findings, meta = parse_grype_json(doc)
        return ScanResult(NAME, "ok", version=meta.get("version"), db_updated_at=meta.get("db_built"),
                          findings=findings, duration_ms=res.duration_ms, raw=raw,
                          os_family=meta.get("os_family"), os_name=meta.get("os_name"))
