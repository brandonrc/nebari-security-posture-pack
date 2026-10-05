"""posture.scap.detect: os-release, product probes, benchmark candidates."""

from __future__ import annotations

import os

from posture.scap.detect import Detection, candidates_for, detect, load_candidates, parse_os_release


def _root(tmp_path, files: dict[str, bytes], links: dict[str, str] | None = None):
    r = tmp_path / "r"
    for name, data in files.items():
        p = r / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    for name, target in (links or {}).items():
        p = r / name
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, p)
    r.mkdir(exist_ok=True)
    return r


def test_parse_os_release_quotes_and_id_like():
    osr = parse_os_release('NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n# c\n')
    assert osr == {"id": "rocky", "versionId": "9.4", "idLike": ["rhel", "centos", "fedora"], "name": "Rocky Linux"}


def test_detect_debian_with_usr_lib_symlink_and_postgres(tmp_path):
    r = _root(tmp_path, {
        "usr/lib/os-release": b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
        "usr/lib/postgresql/16/bin/postgres": b"\x7fELF....postgres (PostgreSQL) 16.4 (Debian 16.4-1)\x00",
        "var/lib/dpkg/status": b"Package: libc6\n", "bin/dash": b"x",
    }, {"etc/os-release": "../usr/lib/os-release", "bin/sh": "dash"})
    det = detect(r)
    assert det.os["id"] == "debian" and det.os["versionId"] == "12" and not det.distroless
    assert det.products == [{"name": "postgresql", "version": "16", "path": "/usr/lib/postgresql/16/bin/postgres"}]
    keys = [c["key"] for c in candidates_for(det)]
    assert keys[0] == "disa-postgresql" and "ssg-debian12" in keys


def test_detect_versions_from_binaries(tmp_path):
    r = _root(tmp_path, {"etc/alpine-release": b"3.20.3\n", "usr/sbin/nginx": b"junk nginx/1.27.1 junk",
                         "usr/local/tomcat/RELEASE-NOTES": b"Apache Tomcat Version 10.1.30\n",
                         "lib/apk/db/installed": b"P:musl\n"})
    det = detect(r)
    assert det.os == {"id": "alpine", "versionId": "3.20.3"}
    assert {p["name"]: p["version"] for p in det.products} == {"nginx": "1.27.1", "tomcat": "10.1.30"}
    # Alpine has no OS benchmark; the products have DISA (manual) candidates only
    assert {c["family"] for c in candidates_for(det)} == {"nginx", "tomcat"}


def test_distroless_and_scratch(tmp_path):
    r = _root(tmp_path, {"etc/os-release": b'ID=debian\nVERSION_ID="12"\n', "var/lib/dpkg/status.d/base": b"x"})
    det = detect(r)
    assert det.distroless and det.os.get("variant") == "distroless"
    assert [c["key"] for c in candidates_for(det)] == ["ssg-debian12"]  # still Debian 12 content
    empty = detect(_root(tmp_path / "e", {"app": b"static binary"}))
    assert empty.os == {} and empty.distroless and candidates_for(empty) == []


def test_prefer_disa_orders_sources():
    det = Detection(os={"id": "rhel", "versionId": "9.4"})
    assert [c["key"] for c in candidates_for(det, prefer_disa=True)] == ["disa-rhel9", "ssg-rhel9"]
    assert [c["key"] for c in candidates_for(det, prefer_disa=False)] == ["ssg-rhel9", "disa-rhel9"]
    assert [c["key"] for c in candidates_for(Detection(os={"id": "ubuntu", "versionId": "24.04"}))] == ["ssg-ubuntu2404"]


def test_builtin_catalogue_is_well_formed_and_extra_file(tmp_path):
    cands = load_candidates()
    assert len({c["key"] for c in cands}) == len(cands)
    assert all(c["source"] in ("ssg", "disa") for c in cands)
    extra = tmp_path / "extra.yaml"
    extra.write_text('candidates:\n  - {key: mine, family: f, source: custom, match: {os.id: "^x$"},'
                     ' datastreams: ["a.xml"], profiles: ["p"]}\n')
    det = Detection(os={"id": "x"})
    assert [c["key"] for c in candidates_for(det, extra=str(extra))] == ["mine"]
