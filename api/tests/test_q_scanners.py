"""Scanner adapters: parser edge cases and the health/version/DB-status paths (quality floors).

The main parse paths are covered against real fixtures in test_scanners.py; this file covers the
branches those fixtures do not reach (missing fields, CVSS-only severities, wrapped Clair reports,
non-JSON tool output) and the backend probes via httpx.MockTransport / fake binaries.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime

import httpx
import pytest

from posture.scanners import base, clair, grype, trivy
from posture.scanners.base import Finding, extract_cve, first_float, parse_time, read_capped, scratch_dir
from posture.severity import max_severity, normalize_severity, severity_rank, zero_counts


def fake_bin(tmp_path, name, script):
    (tmp_path / "bin").mkdir(exist_ok=True)
    p = tmp_path / "bin" / name
    p.write_text("#!/bin/sh\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


@pytest.fixture
def http(monkeypatch):
    """Route every httpx.AsyncClient through a handler table {path: response | exception}."""
    routes: dict[str, object] = {}
    real = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        r = routes.get(request.url.path)
        if isinstance(r, Exception):
            raise r
        if r is None:
            return httpx.Response(404)
        return r  # type: ignore[return-value]

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return routes


# ---------------------------------------------------------------- severity

@pytest.mark.parametrize(("raw", "norm"), [
    (None, "unknown"), ("", "unknown"), ("  CRITICAL ", "critical"), ("Important", "high"), ("moderate", "medium"),
    ("minor", "low"), ("informational", "negligible"), ("none", "negligible"), ("bogus", "unknown"), (7, "unknown"),
])
def test_normalize_severity(raw, norm):
    assert normalize_severity(raw) == norm


def test_severity_ranking_helpers():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("negligible") > severity_rank("unknown")
    assert severity_rank("nonsense") == 0
    assert max_severity(["low", "critical", "medium"]) == "critical"
    assert max_severity([]) == "unknown"
    assert zero_counts() == {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}


# ---------------------------------------------------------------- base helpers

def test_extract_cve_and_first_float():
    assert extract_cve(None, "", "see cve-2024-1234 for details") == "CVE-2024-1234"
    assert extract_cve("GHSA-xxxx-yyyy-zzzz") is None
    assert first_float(None, "", "x", 0, "-1", "7.5") == 7.5
    assert first_float(None, []) is None


@pytest.mark.parametrize(("value", "expected"), [
    ("2026-01-02T03:04:05Z", datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)),
    ("2026-01-02T03:04:05.123456789Z", datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)),
    ("2026-01-02T03:04:05", datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)),  # naive -> UTC
    ("not a date", None), ("", None), (None, None), (12345, None),
])
def test_parse_time(value, expected):
    assert parse_time(value) == expected


def test_finding_as_dict_round_trip():
    f = Finding("CVE-1", "high", "openssl", "1.0", "1.1", "deb", "trivy", 7.5, "t", "u")
    d = f.as_dict()
    assert d["vulnId"] == "CVE-1" and d["severity"] == "high" and d["package"] == "openssl"


def test_read_capped_and_scratch_dir(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"abc\xffdef")
    assert read_capped(str(p), 4) == "abc�"
    assert scratch_dir(str(tmp_path)) == str(tmp_path / "tmp")
    blocker = tmp_path / "file"
    blocker.write_text("")
    # cache dir is not a directory: fall back to the system temp dir
    assert scratch_dir(str(blocker)) != str(blocker / "tmp")


# ---------------------------------------------------------------- trivy

def test_trivy_findings_edge_cases():
    res = {"Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": ""},  # skipped
        {"VulnerabilityID": "GHSA-aaaa-bbbb-cccc", "PkgName": "lib", "Severity": "MEDIUM",
         "CVSS": {"ghsa": {"V3Score": 6.1}, "bogus": "x"}, "Description": "d" * 300},
        {"VulnerabilityID": "CVE-2025-1", "PkgName": "p", "Severity": "HIGH", "CVSS": {"nvd": {"V40Score": 8.7}}},
    ]}
    a, b = trivy.trivy_findings(res)
    assert (a.vuln_id, a.cvss, a.pkg_type, len(a.title)) == ("GHSA-aaaa-bbbb-cccc", 6.1, "lang-pkgs", 200)
    assert (b.vuln_id, b.severity, b.cvss) == ("CVE-2025-1", "high", 8.7)
    assert trivy.parse_trivy_json({}) == ([], {"version": None})


def test_trivy_argv_rejects_bad_oci_paths(tmp_path):
    s = trivy.TrivyScanner("http://t/", "trivy", str(tmp_path))
    assert s.server_url == "http://t"
    with pytest.raises(ValueError):
        s.argv("oci-dir:relative/path", False, 10)
    with pytest.raises(ValueError):
        s.argv("oci-dir:/cache/../etc", False, 10)
    assert s.argv("oci-dir:/cache/oci/abc", False, 10)[-2:] == ["--input", "/cache/oci/abc"]


async def test_trivy_probes(http, tmp_path):
    s = trivy.TrivyScanner("http://trivy:4954", fake_bin(tmp_path, "trivy", 'echo "Version: 0.75.0"\n'), str(tmp_path))
    http["/version"] = httpx.Response(200, json={"Version": "0.75.0",
                                                 "VulnerabilityDB": {"UpdatedAt": "2026-10-01T00:00:00Z"}})
    http["/healthz"] = httpx.Response(200, text="ok")
    assert await s.version() == "0.75.0"
    assert await s.db_updated_at() == datetime(2026, 10, 1, tzinfo=UTC)
    assert await s.healthy() == (True, None)
    http["/healthz"] = httpx.Response(503)
    assert await s.healthy() == (False, "healthz 503")
    http["/healthz"] = httpx.ConnectError("refused")
    ok, err = await s.healthy()
    assert not ok and "unreachable" in err


async def test_trivy_version_falls_back_to_the_client_binary(http, tmp_path):
    http["/version"] = httpx.ConnectError("refused")
    s = trivy.TrivyScanner("http://trivy:4954", fake_bin(tmp_path, "trivy", 'echo "Version: 0.75.0"\n'), str(tmp_path))
    assert await s.version() == "0.75.0"
    assert await s.db_updated_at() is None
    empty = trivy.TrivyScanner("http://trivy:4954", fake_bin(tmp_path, "trivy2", "true\n"), str(tmp_path))
    assert await empty.version() is None


async def test_trivy_scan_error_paths(tmp_path):
    bad = trivy.TrivyScanner("http://t", fake_bin(tmp_path, "trivy", "echo boom >&2; exit 3\n"), str(tmp_path))
    r = await bad.scan("reg.io/a:1", timeout=30)
    assert r.status == "error" and "boom" in r.error
    garbage = trivy.TrivyScanner("http://t", fake_bin(tmp_path, "trivy3", "echo '{not json'\n"), str(tmp_path))
    r = await garbage.scan("reg.io/a:1", timeout=30)
    assert r.status == "error" and "invalid JSON" in r.error and r.raw_gz
    r = await garbage.scan("oci-dir:../x", timeout=30)
    assert r.status == "error" and "refusing" in r.error


# ---------------------------------------------------------------- grype

def test_grype_finding_edge_cases():
    assert grype.grype_finding({"vulnerability": {}}) is None
    f = grype.grype_finding({
        "vulnerability": {"id": "GHSA-1111-2222-3333", "severity": "Low", "fix": {"state": "not-fixed"},
                          "urls": ["https://example.org/a"], "cvss": [{"type": "Secondary", "metrics": {"baseScore": 3.1}}]},
        "relatedVulnerabilities": [{"id": "CVE-2024-9999", "description": "line one\nline two",
                                    "cvss": [{"type": "Primary", "metrics": {"baseScore": 5.5}}]}],
        "artifact": {"name": "pkg", "version": "1", "type": "python"}})
    assert (f.vuln_id, f.fixed_version, f.title, f.url, f.cvss) == ("CVE-2024-9999", None, "line one",
                                                                     "https://example.org/a", 3.1)
    g = grype.grype_finding({"vulnerability": {"id": "X-1", "fix": {"state": "fixed", "versions": ["2", "3"]}},
                             "relatedVulnerabilities": [{"id": "Y", "cvss": [{"metrics": {"baseScore": 9.8}}]}]})
    assert (g.vuln_id, g.fixed_version, g.cvss, g.package) == ("X-1", "2, 3", 9.8, "")


def test_grype_meta_db_built_in_status():
    meta = grype.grype_meta({"version": "0.120.0", "db": {"status": {"built": "2026-09-30T00:00:00Z"}}},
                            {"name": "alpine", "version": "3.17.0"})
    assert meta == {"version": "0.120.0", "os_family": "alpine", "os_name": "3.17.0",
                    "db_built": datetime(2026, 9, 30, tzinfo=UTC)}
    assert grype.grype_meta(None, None) == {"version": None}


async def test_grype_tool_commands(tmp_path):
    script = ('case "$1 $2" in\n'
              '  "version -o") echo \'{"version": "0.120.0"}\' ;;\n'
              '  "db status") echo \'{"built": "2026-09-30T00:00:00Z", "valid": true}\' ;;\n'
              '  "db update") exit 0 ;;\n'
              'esac\n')
    s = grype.GrypeScanner(fake_bin(tmp_path, "grype", script), str(tmp_path), docker_config="/dc")
    assert s.env()["DOCKER_CONFIG"] == "/dc" and s.env(insecure=True)["GRYPE_REGISTRY_INSECURE_USE_HTTP"] == "true"
    assert await s.version() == "0.120.0"
    assert await s.db_updated_at() == datetime(2026, 9, 30, tzinfo=UTC)
    assert await s.update_db(30) == (True, None)


async def test_grype_tool_failures(tmp_path):
    s = grype.GrypeScanner(fake_bin(tmp_path, "grype", "echo 'db is corrupt' >&2; echo nope; exit 1\n"), str(tmp_path))
    assert await s.version() is None
    st = await s.db_status()
    assert st["valid"] is False and "corrupt" in st["error"]
    ok, err = await s.update_db(30)
    assert not ok and "corrupt" in err
    slow = grype.GrypeScanner(fake_bin(tmp_path, "grype2", "sleep 30\n"), str(tmp_path))
    assert await slow.update_db(0.3) == (False, "grype db update timed out")


async def test_grype_scan_error_paths(tmp_path):
    unsupported = grype.GrypeScanner(fake_bin(tmp_path, "grype", "echo 'unable to detect distro' >&2; exit 1\n"),
                                     str(tmp_path))
    r = await unsupported.scan("reg.io/a:1", timeout=30)
    assert r.status == "unsupported"
    garbage = grype.GrypeScanner(fake_bin(tmp_path, "grype2", "echo '[1,'\n"), str(tmp_path))
    r = await garbage.scan("reg.io/a:1", timeout=30)
    assert r.status == "error" and "invalid JSON" in r.error
    r = await garbage.scan("oci-dir:/does/not/exist", timeout=30)
    assert r.status == "error" and "refusing" in r.error


# ---------------------------------------------------------------- clair

def test_clair_report_unwrapping():
    inner = {"vulnerabilities": {}, "package_vulnerabilities": {}}
    assert clair._unwrap_report([inner]) is inner
    assert clair._unwrap_report({"report": inner}) is inner
    assert clair._unwrap_report({"Report": inner}) is inner
    assert clair._unwrap_report("text") == {}
    assert clair._unwrap_report({"other": 1}) == {"other": 1}


def test_clair_first_json_object_skips_log_noise():
    assert clair._first_json_object('level=info msg="x" {"a": 1} trailing') == {"a": 1}
    with pytest.raises(json.JSONDecodeError):
        clair._first_json_object("no json here")


@pytest.mark.parametrize(("score", "sev"), [(None, "unknown"), (9.8, "critical"), (7.0, "high"), (4.0, "medium"),
                                            (0.1, "low"), (0.0, "negligible")])
def test_severity_from_cvss(score, sev):
    assert clair.severity_from_cvss(score) == sev


def test_clair_cvss_only_severity_and_enrichment_shapes():
    doc = {
        "packages": {"1": {"name": "zlib", "version": "1.2", "kind": "binary"}},
        "distributions": {"1": {"name": "Debian", "version": "12"}},
        "package_vulnerabilities": {"1": ["v1", "v2", "missing"], "2": None},
        "vulnerabilities": {
            "v1": {"name": "CVE-2025-1111", "normalized_severity": "Unknown", "links": "https://example.org/v1 x",
                   "description": "Title line\nmore"},
            "v2": {"name": "DSA-1234-1 zlib", "severity": "", "package": {"name": "zlib-alt", "kind": "source"}},
        },
        "enrichments": {
            "message/vnd.clair.map.vulnerability; enricher=clair.cvss schema=https://csrc.nist.gov/schema/nvd/baseline/1.1/cvss-v3.x.json": [
                {"v1": [{"baseScore": 9.1}, {"baseScore": 5.0}, "junk"], "v2": {"baseScore": 0}}, "junk"],
            "other-enricher": [{"v2": [{"baseScore": 10}]}],
        },
    }
    findings, meta = clair.parse_clair_json(doc)
    by = {f.vuln_id: f for f in findings}
    assert by["CVE-2025-1111"].severity == "critical" and by["CVE-2025-1111"].cvss == 9.1  # CVSS-derived
    assert by["CVE-2025-1111"].url == "https://example.org/v1" and by["CVE-2025-1111"].title == "Title line"
    assert by["DSA-1234-1"].severity == "unknown" and by["DSA-1234-1"].cvss is None  # non-cvss enricher ignored
    assert by["DSA-1234-1"].package == "zlib"
    assert meta == {"os_family": "Debian", "os_name": "12"}


@pytest.mark.parametrize(("host", "capable"), [
    ("localhost:5000", True), ("registry.local", True), ("10.0.0.5:5000", True), ("8.8.8.8", False),
    ("registry.example.org:5000", False), ("[::1]:5000", False),
])
def test_plain_http_capable(host, capable):
    assert clair._plain_http_capable(host) is capable


def test_pin_insecure_host(monkeypatch):
    assert clair.pin_insecure_host("nohost") == "nohost"
    assert clair.pin_insecure_host("localhost:5000/a:1") == "localhost:5000/a:1"
    monkeypatch.setattr(clair.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("10.1.2.3", 0))])
    assert clair.pin_insecure_host("registry.svc.example:5000/a:1") == "10.1.2.3:5000/a:1"
    assert clair.pin_insecure_host("registry.svc.example/a:1") == "10.1.2.3/a:1"
    monkeypatch.setattr(clair.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("8.8.4.4", 0))])
    assert clair.pin_insecure_host("public.example/a:1") == "public.example/a:1"  # public IP: leave the name

    def nxdomain(*a, **k):
        raise OSError("nxdomain")
    monkeypatch.setattr(clair.socket, "getaddrinfo", nxdomain)
    assert clair.pin_insecure_host("gone.example/a:1") == "gone.example/a:1"


async def test_clair_probes(http, tmp_path):
    s = clair.ClairScanner("http://clair:6060/", fake_bin(tmp_path, "clairctl", "echo 'clairctl version v4.9.0' >&2\n"),
                           str(tmp_path))
    assert await s.version() == "4.9.0"
    http["/indexer/api/v1/index_state"] = httpx.Response(200, json={"state": "x"})
    assert await s.healthy() == (True, None)
    http["/indexer/api/v1/index_state"] = httpx.Response(500)
    assert await s.healthy() == (False, "index_state 500")
    http["/indexer/api/v1/index_state"] = httpx.ConnectError("refused")
    assert (await s.healthy())[0] is False
    http["/matcher/api/v1/internal/update_operation"] = httpx.Response(200, json={
        "debian": [{"date": "2026-09-01T00:00:00Z"}, {"date": "bad"}], "alpine": [{"date": "2026-09-02T00:00:00Z"}],
        "empty": None})
    assert await s.db_updated_at() == datetime(2026, 9, 2, tzinfo=UTC)
    http["/matcher/api/v1/internal/update_operation"] = httpx.Response(503)
    assert await s.update_operations() is None and await s.db_updated_at() is None
    blank = clair.ClairScanner("http://clair:6060", fake_bin(tmp_path, "clairctl2", "true\n"), str(tmp_path))
    assert await blank.version() is None


def test_clair_config_path_is_rewritten_when_missing(tmp_path):
    s = clair.ClairScanner("http://clair:6060", "clairctl", str(tmp_path))
    p1 = s.config_path()
    assert s.config_path() == p1
    import os
    os.remove(p1)
    assert os.path.exists(s.config_path())


async def test_clair_scan_error_paths(tmp_path):
    bad = clair.ClairScanner("http://clair:6060", fake_bin(tmp_path, "clairctl", "echo nope >&2; exit 2\n"),
                             str(tmp_path))
    r = await bad.scan("reg.io/a:1", timeout=30)
    assert r.status == "error" and "nope" in r.error
    junk = clair.ClairScanner("http://clair:6060", fake_bin(tmp_path, "clairctl2", "echo 'no json at all'\n"),
                              str(tmp_path))
    r = await junk.scan("reg.io/a:1", timeout=30)
    assert r.status == "error"


def test_base_scanner_is_abstract():
    assert base.Scanner.name == "base"


# ---------------------------------------------------------------- raw output packing / process helpers

def test_pack_raw_file_and_text_truncate_to_a_summary(tmp_path):
    import gzip
    import os

    p = tmp_path / "raw.json"
    p.write_bytes(os.urandom(256 * 1024))  # incompressible
    gz, size, cut = base.pack_raw_file(str(p), "trivy", max_gz=1024, findings=3, meta={"os_family": "alpine"})
    doc = json.loads(gzip.decompress(gz))
    assert cut and size == 256 * 1024
    assert doc["truncated"] and doc["findingsCount"] == 3 and doc["metadata"] == {"os_family": "alpine"}
    gz, size, cut = base.pack_raw_text("x" * 100, "grype", max_gz=1024)
    assert not cut and gzip.decompress(gz) == b"x" * 100
    gz, size, cut = base.pack_raw_text(os.urandom(4096).hex(), "grype", max_gz=64)
    assert cut and json.loads(gzip.decompress(gz))["scanner"] == "grype"


def test_signal_group_falls_back_to_the_process(monkeypatch):
    sent = []

    class Proc:
        pid = 999999

        def send_signal(self, sig):
            sent.append(sig)

    def denied(pid, sig):
        raise PermissionError

    monkeypatch.setattr(base.os, "killpg", denied)
    base._signal_group(Proc(), 15)
    assert sent == [15]

    class Gone(Proc):
        def send_signal(self, sig):
            raise ProcessLookupError

    base._signal_group(Gone(), 9)  # already reaped: no error


async def test_finish_readers_gives_up_on_stuck_or_failed_readers(monkeypatch):
    import asyncio

    async def boom():
        raise RuntimeError("reader crashed")

    assert await base._finish_readers(asyncio.ensure_future(boom())) == (True, True)
    monkeypatch.setattr(base.asyncio, "wait_for", _instant_timeout)
    stuck = asyncio.ensure_future(asyncio.sleep(3600))
    assert await base._finish_readers(stuck) == (True, True)
    await asyncio.sleep(0)
    assert stuck.cancelled()


async def _instant_timeout(aw, timeout):
    aw.cancel() if hasattr(aw, "cancel") else None
    raise TimeoutError


async def test_trivy_scan_timeout_and_docker_config(tmp_path):
    s = trivy.TrivyScanner("http://t", fake_bin(tmp_path, "trivy", 'echo "$DOCKER_CONFIG" > ' + str(tmp_path / "dc") + "\nsleep 30\n"),
                           str(tmp_path), docker_config="/run/dockercfg")
    r = await s.scan("reg.io/a:1", timeout=1)
    assert r.status == "timeout"
    assert (tmp_path / "dc").read_text().strip() == "/run/dockercfg"
