"""Scanner memory (architecture review M2): grype concurrency cap, streaming parse from the
output file, raw JSON stored gzip'd and never cut into invalid JSON, size admission."""

from __future__ import annotations

import asyncio
import gzip
import json
import stat

from posture.admission import manifest_size, order_for_admission, pick_platform
from posture.scanners.base import ScanResult, pack_raw_file, pack_raw_text
from posture.scanners.grype import GrypeScanner, parse_grype_file, parse_grype_json
from posture.scanners.trivy import TrivyScanner, parse_trivy_file, parse_trivy_json


def _key(fs):
    return sorted((f.vuln_id, f.package, f.severity, f.fixed_version, f.cvss, f.title, f.url) for f in fs)


def test_streaming_parse_matches_full_parse(fixtures_dir):
    for full, stream, name in ((parse_grype_json, parse_grype_file, "grype.json"),
                               (parse_trivy_json, parse_trivy_file, "trivy.json")):
        path = str(fixtures_dir / name)
        f1, m1 = full(json.loads((fixtures_dir / name).read_text()))
        f2, m2 = stream(path)
        assert _key(f1) == _key(f2) and f1
        assert m1 == m2


def test_raw_pack_keeps_valid_json(tmp_path):
    doc = {"matches": [{"vulnerability": {"id": f"CVE-2024-{i:05d}", "description": "x" * 50 + str(i)}}
                       for i in range(5000)], "descriptor": {"version": "0.1"}}
    p = tmp_path / "out.json"
    p.write_text(json.dumps(doc))
    gz, size, cut = pack_raw_file(str(p), "grype", max_gz=10 * 1024 * 1024)
    assert not cut and size == p.stat().st_size and json.loads(gzip.decompress(gz)) == doc
    gz, size, cut = pack_raw_file(str(p), "grype", max_gz=2048, findings=5000, meta={"version": "0.1"})
    small = json.loads(gzip.decompress(gz))  # still valid JSON: the findings payload is dropped
    assert cut and small["truncated"] is True and small["rawSize"] == size and small["findingsCount"] == 5000
    assert small["metadata"] == {"version": "0.1"} and "matches" not in small
    gz, _, cut = pack_raw_text(json.dumps(doc), "trivy", max_gz=2048)
    assert cut and json.loads(gzip.decompress(gz))["scanner"] == "trivy"


def test_worker_pack_raw_enforces_setting():
    from posture.worker import pack_raw

    big = gzip.compress(json.dumps({"x": list(range(100000))}).encode())
    r = ScanResult("grype", "ok", raw_gz=big, raw_size=999)
    gz, size, cut = pack_raw(r, max_gz=1024)
    assert cut and size == 999 and json.loads(gzip.decompress(gz))["truncated"] is True
    assert pack_raw(r, max_gz=len(big)) == (big, 999, False)
    assert pack_raw(ScanResult("t", "ok", raw="{}"), 1024)[0] == gzip.compress(b"{}", compresslevel=6)
    assert pack_raw(ScanResult("t", "error"), 1024) == (None, 0, False)


def _fake_bin(tmp_path, name, script):
    (tmp_path / "bin").mkdir(exist_ok=True)
    p = tmp_path / "bin" / name
    p.write_text("#!/bin/sh\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


async def test_grype_concurrency_cap(tmp_path, fixtures_dir):
    binary = _fake_bin(tmp_path, "grype", f"sleep 0.4\ncat {fixtures_dir / 'grype.json'}\n")
    sc = GrypeScanner(binary, str(tmp_path), max_concurrent=2)
    peak = 0

    async def sample():
        nonlocal peak
        while True:
            peak = max(peak, sc.running)
            await asyncio.sleep(0.01)

    sampler = asyncio.create_task(sample())
    results = await asyncio.gather(*(sc.scan(f"reg:5000/a{i}:b", timeout=30) for i in range(5)))
    sampler.cancel()
    assert all(r.status == "ok" and len(r.findings) == 4 and r.raw_gz for r in results)
    assert peak == 2  # 5 images in parallel, never more than GRYPE_MAX_CONCURRENT grype processes


async def test_oci_dir_sources(tmp_path, fixtures_dir):
    layout = tmp_path / "images" / "sha256-abc"
    layout.mkdir(parents=True)
    g = _fake_bin(tmp_path, "grype", f'echo "$@" > {tmp_path}/gargs\ncat {fixtures_dir / "grype.json"}\n')
    r = await GrypeScanner(g, str(tmp_path)).scan(f"oci-dir:{layout}", timeout=30)
    assert r.status == "ok" and (tmp_path / "gargs").read_text().split()[-1] == f"oci-dir:{layout}"
    bad = await GrypeScanner(g, str(tmp_path)).scan("oci-dir:../../etc", timeout=30)
    assert bad.status == "error" and "refusing" in bad.error
    t = _fake_bin(tmp_path, "trivy", f'echo "$@" > {tmp_path}/targs\ncat {fixtures_dir / "trivy.json"}\n')
    r = await TrivyScanner("http://trivy:4954", t, str(tmp_path)).scan(f"oci-dir:{layout}", timeout=30)
    args = (tmp_path / "targs").read_text().split()
    assert r.status == "ok" and args[-2:] == ["--input", str(layout)] and "--" not in args


def test_admission_helpers():
    idx = {"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {"digest": "sha256:att", "platform": {"os": "unknown", "architecture": "unknown"}},
        {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}}]}
    assert pick_platform(idx, "amd64") == "sha256:amd" and pick_platform(idx, "s390x") == "sha256:arm"
    assert manifest_size({"config": {"size": 10}, "layers": [{"size": 100}, {"size": 5}]}) == 115
    assert manifest_size({"manifests": []}) is None
    gb = 1024**3
    now_, later = order_for_admission([1, 2, 3, 4], {1: 30 * gb, 2: None, 3: 1 * gb, 4: 25 * gb}, 20 * gb)
    assert now_ == [2, 3] and later == [4, 1]
    assert order_for_admission([1, 2], {1: 30 * gb}, 0) == ([1, 2], [])


def test_report_child_env_is_minimal(monkeypatch):
    from posture.report_worker import child_env

    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@db/x")
    monkeypatch.setenv("REPORTS_DIR", "/data/reports")
    monkeypatch.setenv("OIDC_ISSUERS", "https://kc")
    monkeypatch.setenv("CONTROLS_KEYCLOAK_CLIENT_SECRET", "s3")
    monkeypatch.setenv("DB_PASSWORD", "pw")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "k")
    monkeypatch.setenv("RANDOM_UNRELATED", "x")
    env = child_env()
    assert env["DATABASE_URL"].endswith("@db/x") and env["REPORTS_DIR"] == "/data/reports" and env["PATH"]
    for k in ("OIDC_ISSUERS", "CONTROLS_KEYCLOAK_CLIENT_SECRET", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY",
              "RANDOM_UNRELATED"):
        assert k not in env
