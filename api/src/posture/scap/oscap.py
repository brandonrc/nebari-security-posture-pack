"""OpenSCAP adapter (DESIGN §14): `oscap-chroot <rootfs> xccdf eval … --results-arf <arf>` and the
ARF / XCCDF TestResult parser that turns results into normalised rows.

oscap exit codes: 0 every rule passed, 2 at least one rule failed, 1 error. OVAL probes read the
rootfs through OSCAP_PROBE_ROOT (set by oscap-chroot); rules that need a running system
(services, processes, sysctl, auditd) come back `notchecked` / `notapplicable` and are kept as
such. Nothing is fetched from the network (`--fetch-remote-resources` is never passed).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..scanners.base import parse_time, run_proc, tail
from .content import local

RESULTS = ("pass", "fail", "notapplicable", "notchecked", "error", "unknown", "informational")
RESULT_MAP = {"pass": "pass", "fixed": "pass", "fail": "fail", "notapplicable": "notapplicable",
              "notchecked": "notchecked", "error": "error", "unknown": "unknown", "informational": "informational"}
SEVERITY_CAT = {"high": "cat1", "medium": "cat2", "low": "cat3"}
_V = re.compile(r"\bV-\d+\b")
_SV = re.compile(r"SV-\d+r\d+_rule(?![A-Za-z0-9])")
_CCI = re.compile(r"^CCI-\d{6}$")


def severity_cat(sev: str | None) -> str:
    """XCCDF severity -> DISA category (unknown / info -> cat3, the lowest weight)."""
    return SEVERITY_CAT.get((sev or "").strip().lower(), "cat3")


@dataclass
class RuleResult:
    rule_id: str
    result: str
    severity: str  # cat1 | cat2 | cat3
    title: str = ""
    stig_id: str | None = None  # V- (vulnerability / group id) when known, else SV-
    vuln_id: str | None = None
    sv_id: str | None = None
    rule_version: str | None = None  # STIG ID, e.g. RHEL-09-412035
    cci: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    srg: list[str] = field(default_factory=list)
    fix_text: str | None = None
    group_title: str | None = None


@dataclass
class EvalResult:
    status: str  # evaluated | notApplicable | error | timeout
    rules: list[RuleResult] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    benchmark_id: str | None = None
    profile_id: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    score: float | None = None  # oscap's own XCCDF score (not ours)
    error: str | None = None
    duration_ms: int = 0
    returncode: int | None = None
    stderr_tail: str = ""


def count(rules: list[RuleResult]) -> dict[str, int]:
    out = {r: 0 for r in RESULTS}
    for r in rules:
        out[r.result] = out.get(r.result, 0) + 1
    return out


def parse_results(path: Path, meta: dict[str, dict[str, Any]] | None = None) -> EvalResult:
    """Parse an ARF (or plain XCCDF results) file: the first TestResult wins. `meta` is the rule
    metadata of the benchmark (content.rule_metadata) for titles, V-/SV- ids, CCIs, fix text."""
    meta = meta or {}
    res = EvalResult(status="evaluated")
    in_tr = False
    cur: dict[str, Any] | None = None
    seen_tr = False
    for event, el in ET.iterparse(path, events=("start", "end")):
        name = local(el.tag)
        if event == "start":
            if name == "TestResult" and not seen_tr:
                in_tr = True
                res.started_at = parse_time(el.get("start-time"))
                res.finished_at = parse_time(el.get("end-time"))
            elif in_tr and name == "rule-result":
                cur = {"idref": el.get("idref", ""), "severity": el.get("severity"), "result": None,
                       "idents": [], "role": el.get("role")}
            continue
        if not in_tr:
            if name in ("Rule", "Group", "Value", "Profile", "component", "def", "definition"):
                el.clear()
            continue
        if name == "benchmark" and el.get("id"):
            res.benchmark_id = el.get("id")
        elif name == "profile" and el.get("idref") and cur is None:
            res.profile_id = el.get("idref")
        elif name == "result" and cur is not None:
            cur["result"] = (el.text or "").strip().lower()
        elif name == "ident" and cur is not None:
            cur["idents"].append(("".join(el.itertext()).strip(), el.get("system") or ""))
        elif name == "rule-result" and cur is not None:
            raw = cur["result"] or "unknown"
            if raw != "notselected":
                res.rules.append(_row(cur, RESULT_MAP.get(raw, "unknown"), meta.get(cur["idref"]) or {}))
            cur = None
            el.clear()
        elif name == "score" and res.score is None:
            try:
                res.score = float(el.text or "")
            except ValueError:
                pass
        elif name == "TestResult":
            in_tr = False
            seen_tr = True
            el.clear()
    if not seen_tr:
        res.status = "error"
        res.error = "no XCCDF TestResult in the results file"
    res.counts = count(res.rules)
    evaluated = res.counts["pass"] + res.counts["fail"]
    if res.status == "evaluated" and res.rules and not evaluated and res.counts["notapplicable"] == len(res.rules):
        res.status = "notApplicable"
    return res


def _row(cur: dict[str, Any], result: str, m: dict[str, Any]) -> RuleResult:
    rid = cur["idref"]
    cci = list(m.get("cci") or [])
    vuln_id, sv_id = m.get("vulnId"), m.get("svId")
    for text, system in cur["idents"]:
        if _CCI.match(text) and text not in cci:
            cci.append(text)
        elif _SV.fullmatch(text):
            sv_id = sv_id or text
        elif re.fullmatch(r"V-\d+", text):
            vuln_id = vuln_id or text
    if not sv_id:
        m2 = _SV.search(rid)
        sv_id = m2.group(0) if m2 else None
    return RuleResult(
        rule_id=rid, result=result, severity=severity_cat(cur.get("severity") or m.get("severity")),
        title=m.get("title") or rid.rsplit("_rule_", 1)[-1], stig_id=vuln_id or sv_id, vuln_id=vuln_id, sv_id=sv_id,
        rule_version=m.get("stigId") or m.get("version") or None, cci=sorted(set(cci)), nist=list(m.get("nist") or []),
        srg=list(m.get("srg") or []), fix_text=m.get("fixText"), group_title=m.get("groupTitle") or None)


async def oscap_version(oscap_bin: str = "oscap") -> str | None:
    res = await run_proc([oscap_bin, "--version"], 30)
    if res.returncode != 0:
        return None
    m = re.search(r"\(oscap\)\s+(\S+)", res.stdout) or re.search(r"(\d+\.\d+\.\d+)", res.stdout)
    return m.group(1) if m else None


async def evaluate(rootfs: Path, datastream: Path, profile_id: str, work_dir: Path, *, timeout: float,
                   benchmark_id: str | None = None, meta: dict[str, dict[str, Any]] | None = None,
                   chroot_bin: str = "oscap-chroot", skip_validation: bool = False,
                   html_report: Path | None = None) -> EvalResult:
    """Run one benchmark/profile against a rootfs and parse the ARF."""
    work_dir.mkdir(parents=True, exist_ok=True)
    arf = work_dir / "results-arf.xml"
    arf.unlink(missing_ok=True)
    argv = [chroot_bin, str(rootfs), "xccdf", "eval", "--profile", profile_id, "--results-arf", str(arf)]
    if benchmark_id:
        argv += ["--benchmark-id", benchmark_id]
    if html_report is not None:
        argv += ["--report", str(html_report)]
    if skip_validation:
        argv.append("--skip-valid")
    argv.append(str(datastream))
    started = datetime.now(UTC)
    proc = await run_proc(argv, timeout, stdout_file=str(work_dir / "oscap.stdout"))
    if proc.timed_out:
        return EvalResult(status="timeout", error=f"oscap timed out after {int(timeout)}s", duration_ms=proc.duration_ms,
                          started_at=started, profile_id=profile_id, benchmark_id=benchmark_id)
    if proc.returncode is None:  # binary missing
        return EvalResult(status="error", error=proc.stderr, duration_ms=proc.duration_ms, profile_id=profile_id)
    if proc.returncode not in (0, 2) or not arf.exists():
        return EvalResult(status="error", returncode=proc.returncode, duration_ms=proc.duration_ms,
                          error=f"oscap exited {proc.returncode}: {tail(proc.stderr, 600) or 'no output'}",
                          stderr_tail=tail(proc.stderr, 2000), profile_id=profile_id, benchmark_id=benchmark_id,
                          started_at=started)
    try:
        res = parse_results(arf, meta)
    except ET.ParseError as e:
        return EvalResult(status="error", error=f"unparseable ARF: {e}", duration_ms=proc.duration_ms,
                          profile_id=profile_id, returncode=proc.returncode)
    res.duration_ms = proc.duration_ms
    res.returncode = proc.returncode
    res.stderr_tail = tail(proc.stderr, 2000)
    res.profile_id = res.profile_id or profile_id
    res.benchmark_id = res.benchmark_id or benchmark_id
    res.started_at = res.started_at or started
    return res
