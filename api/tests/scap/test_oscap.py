"""posture.scap.oscap: ARF parsing (always) and a real `oscap-chroot` run (when installed).

The end-to-end test needs OpenSCAP; it is skipped on hosts without it. It runs in the worker image:

    cd api && docker run --rm -u 0 -v "$PWD":/src:ro -w /src -e PYTHONDONTWRITEBYTECODE=1 \\
      --entrypoint sh security-posture-worker:dev -c \\
      'pip install -q --target /tmp/pt pytest==9.1.1 pytest-asyncio==1.4.0 &&
       PYTHONPATH=src:/tmp/pt python -m pytest -q -p no:cacheprovider tests/scap'

(as root, so the privileged rootfs test runs too; the worker image's venv has no pip).
"""

from __future__ import annotations

import shutil

import pytest

from posture.scap import content, oscap

from .helpers import TEST_ARF, TEST_BENCHMARK, TEST_DS, TEST_PROFILE

HAVE_OSCAP = bool(shutil.which("oscap") and shutil.which("oscap-chroot"))


def test_parse_arf_results_with_metadata(tmp_path):
    meta = content.rule_metadata(tmp_path, TEST_DS, "t", TEST_BENCHMARK)
    res = oscap.parse_results(TEST_ARF, meta)
    assert res.status == "evaluated" and res.benchmark_id == TEST_BENCHMARK and res.profile_id == TEST_PROFILE
    assert res.counts["pass"] == 2 and res.counts["fail"] == 1
    by = {r.rule_id.rsplit("_", 1)[-1]: r for r in res.rules}
    assert (by["banner"].result, by["banner"].severity, by["banner"].stig_id, by["banner"].sv_id) == (
        "pass", "cat1", "V-90001", "SV-90001r1_rule")
    assert (by["motd"].result, by["motd"].severity, by["motd"].cci, by["motd"].rule_version) == (
        "fail", "cat3", ["CCI-001384"], "TEST-01-000030")
    assert by["motd"].fix_text == "Write the notice to /etc/motd." and by["rhosts"].nist == ["CM-6"]


def test_parse_results_edge_cases(tmp_path):
    p = tmp_path / "r.xml"
    p.write_text('<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_t_testresult_x">'
                 '<benchmark id="b"/><profile idref="p"/>'
                 '<rule-result idref="xccdf_t_rule_a" severity="medium"><result>notapplicable</result></rule-result>'
                 '<rule-result idref="xccdf_t_rule_b"><result>notselected</result></rule-result>'
                 '<rule-result idref="xccdf_t_rule_SV-1r2_rule" severity="unknown"><result>notapplicable</result>'
                 '<ident system="http://cyber.mil/cci">CCI-000366</ident></rule-result></TestResult>')
    res = oscap.parse_results(p)
    assert res.status == "notApplicable" and len(res.rules) == 2  # notselected dropped
    sv = next(r for r in res.rules if r.rule_id.endswith("_rule"))
    assert sv.sv_id == "SV-1r2_rule" and sv.cci == ["CCI-000366"] and sv.severity == "cat3"
    empty = tmp_path / "e.xml"
    empty.write_text("<x/>")
    assert oscap.parse_results(empty).status == "error"


def test_severity_mapping():
    assert [oscap.severity_cat(s) for s in ("high", "medium", "low", "info", "unknown", None)] == [
        "cat1", "cat2", "cat3", "cat3", "cat3", "cat3"]


async def test_evaluate_reports_missing_binary_and_timeouts(tmp_path):
    res = await oscap.evaluate(tmp_path, TEST_DS, TEST_PROFILE, tmp_path / "w", timeout=5,
                               chroot_bin="/nonexistent/oscap-chroot")
    assert res.status == "error" and "not found" in res.error
    sleeper = tmp_path / "slow.sh"
    sleeper.write_text("#!/bin/sh\nsleep 30\n")
    sleeper.chmod(0o755)
    res = await oscap.evaluate(tmp_path, TEST_DS, TEST_PROFILE, tmp_path / "w", timeout=0.5, chroot_bin=str(sleeper))
    assert res.status == "timeout"


@pytest.mark.skipif(not HAVE_OSCAP, reason="OpenSCAP (oscap, oscap-chroot) not installed; runs in the worker image")
async def test_oscap_chroot_end_to_end(tmp_path):
    """Real OpenSCAP against a temp rootfs: /etc/issue has the banner (pass), no /etc/hosts.equiv
    (pass), no /etc/motd (fail). Proves the OVAL probes read the rootfs, not the host."""
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc/issue").write_text("AUTHORIZED USE ONLY\n")
    meta = content.parse_rules(TEST_DS)
    res = await oscap.evaluate(root, TEST_DS, TEST_PROFILE, tmp_path / "work", timeout=120, meta=meta)
    assert res.status == "evaluated", res.error
    assert {r.rule_id.rsplit("_", 1)[-1]: r.result for r in res.rules} == {"banner": "pass", "rhosts": "pass",
                                                                          "motd": "fail"}
    assert res.returncode == 2 and (tmp_path / "work/results-arf.xml").exists()
    # flip the outcome through the rootfs only
    (root / "etc/issue").write_text("hello\n")
    (root / "etc/motd").write_text("Authorized use only\n")
    (root / "etc/hosts.equiv").write_text("+\n")
    res = await oscap.evaluate(root, TEST_DS, TEST_PROFILE, tmp_path / "work2", timeout=120, meta=meta)
    assert {r.rule_id.rsplit("_", 1)[-1]: r.result for r in res.rules} == {"banner": "fail", "rhosts": "fail",
                                                                          "motd": "pass"}
    assert await oscap.oscap_version() not in (None, "")


def test_probe_warnings_flag_silent_package_probe_failures():
    err = "W: oscap: uname offline\nE: oscap:     dpkginfo_init has failed.\n"
    assert oscap.probe_warnings(err) == ["dpkginfo probe failed: Debian package rules are unreliable"]
    assert oscap.probe_warnings("") == []
