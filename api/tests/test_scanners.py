import json
import gzip
import os
import stat
from datetime import UTC, datetime

import httpx
import pytest

from posture.scanners.base import parse_time, run_proc
from posture.scanners.clair import ClairScanner, parse_clair_json, pin_insecure_host, write_clairctl_config
from posture.scanners.grype import GrypeScanner, parse_grype_json
from posture.scanners.trivy import TrivyScanner, parse_trivy_json


def load(fixtures_dir, name):
    return json.loads((fixtures_dir / name).read_text())


def keyed(findings):
    return {(f.vuln_id, f.package): f for f in findings}


def test_trivy_parser(fixtures_dir):
    findings, meta = parse_trivy_json(load(fixtures_dir, "trivy.json"))
    k = keyed(findings)
    assert set(k) == {("CVE-2024-6119", "libcrypto3"), ("CVE-2023-0464", "libssl3"), ("CVE-2023-42363", "busybox")}
    f = k[("CVE-2024-6119", "libcrypto3")]
    assert f.severity == "high" and f.fixed_version == "3.0.15-r0" and f.installed_version == "3.0.7-r0"
    assert f.pkg_type == "alpine" and f.scanner == "trivy" and f.cvss == 7.5
    assert f.url.startswith("https://avd.aquasec.com/")
    assert k[("CVE-2023-42363", "busybox")].severity == "medium"
    assert meta == {"os_family": "alpine", "os_name": "3.17.0", "version": "0.75.0"}


def test_grype_parser(fixtures_dir):
    findings, meta = parse_grype_json(load(fixtures_dir, "grype.json"))
    k = keyed(findings)
    assert len(k) == 4
    f = k[("CVE-2024-6119", "libcrypto3")]
    assert f.severity == "high" and f.fixed_version == "3.0.15-r0" and f.pkg_type == "apk" and f.cvss == 7.5
    g = k[("CVE-2022-48174", "busybox")]
    assert g.severity == "critical" and g.fixed_version is None
    assert meta["version"] == "0.120.0" and meta["os_family"] == "alpine"
    assert meta["db_built"] == datetime(2026, 10, 2, 6, 31, 53, tzinfo=UTC)


def test_clair_parser(fixtures_dir):
    findings, meta = parse_clair_json(load(fixtures_dir, "clair.json"))
    k = keyed(findings)
    assert set(k) == {("CVE-2024-6119", "libcrypto3"), ("CVE-2023-0464", "libssl3"), ("CVE-2023-42363", "busybox")}
    f = k[("CVE-2024-6119", "libcrypto3")]
    # alpine secdb has no severity -> derived from the cvss enrichment
    assert f.severity == "high" and f.cvss == 7.5 and f.fixed_version == "3.0.15-r0"
    assert f.installed_version == "3.0.7-r0"  # from the installed (binary) package, not the source package
    assert k[("CVE-2023-0464", "libssl3")].severity == "unknown"
    assert meta["os_family"] == "alpine"


def test_clair_parser_wrapped_and_garbage():
    assert parse_clair_json({"report": {"packages": {}, "vulnerabilities": {}, "package_vulnerabilities": {}}})[0] == []
    assert parse_clair_json([])[0] == []


def test_all_three_agree_on_fixture(fixtures_dir):
    from posture.correlate import correlate

    fs = (parse_trivy_json(load(fixtures_dir, "trivy.json"))[0] + parse_grype_json(load(fixtures_dir, "grype.json"))[0]
          + parse_clair_json(load(fixtures_dir, "clair.json"))[0])
    c = {(x.vuln_id, x.package): x for x in correlate(fs, ["trivy", "grype", "clair"])}
    assert c[("CVE-2024-6119", "libcrypto3")].scanners == ["trivy", "grype", "clair"]
    assert c[("CVE-2022-48174", "busybox")].scanners == ["grype"]


def test_parse_time_nanoseconds():
    assert parse_time("2026-10-02T12:48:00.080865328Z") == datetime(2026, 10, 2, 12, 48, 0, 80865, tzinfo=UTC)
    assert parse_time("nope") is None and parse_time(None) is None


def fake_bin(tmp_path, name, script):
    (tmp_path / "bin").mkdir(exist_ok=True)
    p = tmp_path / "bin" / name
    p.write_text("#!/bin/sh\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


async def test_trivy_adapter_runs_binary(tmp_path, fixtures_dir):
    out = fixtures_dir / "trivy.json"
    binary = fake_bin(tmp_path, "trivy", f'echo "$@" > {tmp_path}/args\ncat {out}\n')
    r = await TrivyScanner("http://trivy:4954", binary, str(tmp_path)).scan("reg:5000/a:b", insecure=True, timeout=30)
    assert r.status == "ok" and len(r.findings) == 3 and r.version == "0.75.0" and r.raw_gz
    assert json.loads(gzip.decompress(r.raw_gz)) == json.loads(out.read_text()) and not r.raw_truncated
    args = (tmp_path / "args").read_text()
    assert "--server http://trivy:4954" in args and "--insecure" in args and "--scanners vuln" in args
    assert args.strip().endswith("-- reg:5000/a:b")


async def test_grype_adapter_env_and_registry_scheme(tmp_path, fixtures_dir):
    out = fixtures_dir / "grype.json"
    binary = fake_bin(tmp_path, "grype", f'echo "$@ $GRYPE_DB_CACHE_DIR $GRYPE_REGISTRY_INSECURE_USE_HTTP '
                                         f'$GRYPE_DB_AUTO_UPDATE" > {tmp_path}/args\ncat {out}\n')
    r = await GrypeScanner(binary, str(tmp_path)).scan("reg:5000/a:b", insecure=True, timeout=30)
    assert r.status == "ok" and len(r.findings) == 4
    args = (tmp_path / "args").read_text()
    assert args.startswith("-o json -- registry:reg:5000/a:b")
    assert f"{tmp_path}/grype true false" in args


async def test_grype_db_status(tmp_path, fixtures_dir):
    binary = fake_bin(tmp_path, "grype", f"cat {fixtures_dir / 'grype-db-status.json'}\n")
    assert await GrypeScanner(binary, str(tmp_path)).db_updated_at() == datetime(2026, 10, 2, 6, 31, 53, tzinfo=UTC)


async def test_clair_adapter_uses_config_and_host(tmp_path, fixtures_dir):
    out = fixtures_dir / "clair.json"
    binary = fake_bin(tmp_path, "clairctl", f'echo "$@" > {tmp_path}/args\nprintf "noise\\n"; cat {out}\n')
    sc = ClairScanner("http://clair:6060", binary, str(tmp_path), "registry.local:5000")
    r = await sc.scan("registry.local:5000/x@sha256:" + "a" * 64, insecure=True, timeout=30)
    assert r.status == "ok" and len(r.findings) == 3
    args = (tmp_path / "args").read_text().split()
    assert args[:3] == ["-q", "-c", str(tmp_path / "clairctl" / "config.yaml")]
    assert args[3:10] == ["report", "--host", "http://clair:6060/", "--out", "json", "--",
                          "registry.local:5000/x@sha256:" + "a" * 64]
    assert os.path.exists(tmp_path / "clairctl" / "config.yaml")


async def test_scanner_error_and_timeout(tmp_path):
    bad = fake_bin(tmp_path, "trivy", 'echo "FATAL unable to pull" >&2\nexit 1\n')
    r = await TrivyScanner("http://t", bad, str(tmp_path)).scan("x", timeout=30)
    assert r.status == "error" and "unable to pull" in r.error
    slow = fake_bin(tmp_path, "grype", "sleep 5\n")
    r = await GrypeScanner(slow, str(tmp_path)).scan("x", timeout=0.5)
    assert r.status == "timeout"
    r = await GrypeScanner(str(tmp_path / "missing"), str(tmp_path)).scan("x", timeout=5)
    assert r.status == "error" and "not found" in r.error
    garbage = fake_bin(tmp_path, "clairctl", "echo not-json\n")
    r = await ClairScanner("http://c", garbage, str(tmp_path)).scan("x", timeout=5)
    assert r.status == "error"


async def test_run_proc_output():
    res = await run_proc(["sh", "-c", "echo hi; echo err >&2; exit 3"], 5)
    assert (res.returncode, res.stdout.strip(), res.stderr.strip(), res.timed_out) == (3, "hi", "err", False)


async def test_trivy_server_metadata(monkeypatch, fixtures_dir):
    payload = load(fixtures_dir, "trivy-server-version.json")

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **kw):
            assert url == "http://trivy:4954/version"
            return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

    monkeypatch.setattr("posture.scanners.trivy.httpx.AsyncClient", FakeClient)
    sc = TrivyScanner("http://trivy:4954")
    assert await sc.version() == "0.75.0"
    assert (await sc.db_updated_at()).date().isoformat() == "2026-10-02"


async def test_clair_db_updated_at(monkeypatch, fixtures_dir):
    payload = load(fixtures_dir, "clair-update-operations.json")

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **kw):
            return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

    monkeypatch.setattr("posture.scanners.clair.httpx.AsyncClient", FakeClient)
    dt = await ClairScanner("http://clair:6060").db_updated_at()
    assert dt == datetime(2026, 10, 2, 19, 22, 58, 177413, tzinfo=UTC)


def test_clairctl_config_template(tmp_path):
    p = write_clairctl_config(str(tmp_path), "registry.container-registry.svc.cluster.local:5000")
    import yaml

    cfg = yaml.safe_load(open(p))
    assert cfg["http_listen_addr"] == ":6060" and cfg["auth"] == {}


@pytest.mark.parametrize("ref,expected", [
    ("registry.container-registry.svc.cluster.local:5000/a:b", "registry.container-registry.svc.cluster.local:5000/a:b"),
    ("localhost:32000/a:b", "localhost:32000/a:b"),
    ("10.152.183.10:5000/a:b", "10.152.183.10:5000/a:b"),
])
def test_pin_insecure_host_passthrough(ref, expected):
    assert pin_insecure_host(ref) == expected
