"""Build OCI image layouts on disk for the posture.scap tests (no registry, no skopeo)."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DS = FIXTURES / "posture-test-ds.xml"
TEST_ARF = FIXTURES / "posture-test-arf.xml"
TEST_PROFILE = "xccdf_test.posture_profile_stig"
TEST_BENCHMARK = "xccdf_test.posture_benchmark_minimal"
OS_RELEASE = b'ID=postureos\nVERSION_ID="1.0"\nPRETTY_NAME="Posture Test OS 1.0"\n'


def _blob(root: Path, data: bytes) -> str:
    d = "sha256:" + hashlib.sha256(data).hexdigest()
    p = root / "blobs" / "sha256" / d.split(":", 1)[1]
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return d


def layer_tar(entries: list[tuple], compress: bool = True) -> bytes:
    """entries: ("file", name, bytes, mode?, uid?, gid?, xattrs?) | ("dir", name, mode?) |
    ("symlink", name, target) | ("hardlink", name, target) | ("whiteout", name) | ("opaque", dirname) |
    ("fifo", name) | ("chr", name)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for e in entries:
            kind, name = e[0], e[1]
            ti = tarfile.TarInfo(name)
            ti.mtime = 1_700_000_000
            data = None
            if kind == "file":
                data = e[2]
                ti.size = len(data)
                ti.mode = e[3] if len(e) > 3 else 0o644
                ti.uid = e[4] if len(e) > 4 else 0
                ti.gid = e[5] if len(e) > 5 else 0
                if len(e) > 6 and e[6]:
                    ti.pax_headers = {f"SCHILY.xattr.{k}": v for k, v in e[6].items()}
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = e[2] if len(e) > 2 else 0o755
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = e[2]
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = e[2]
            elif kind == "whiteout":
                parent, _, base = name.rpartition("/")
                ti.name = (parent + "/" if parent else "") + ".wh." + base
                data = b""
            elif kind == "opaque":
                ti.name = name.rstrip("/") + "/.wh..wh..opq"
                data = b""
            elif kind == "fifo":
                ti.type = tarfile.FIFOTYPE
            elif kind == "chr":
                ti.type = tarfile.CHRTYPE
                ti.devmajor, ti.devminor = 1, 3
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    raw = buf.getvalue()
    return gzip.compress(raw) if compress else raw


def make_layout(root: Path, layers: list[list[tuple]], config: dict[str, Any] | None = None,
                compress: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    descs = []
    for entries in layers:
        data = layer_tar(entries, compress)
        descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if compress else ""),
                      "digest": _blob(root, data), "size": len(data)})
    cfg = json.dumps(config or {"architecture": "amd64", "os": "linux"}).encode()
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": _blob(root, cfg),
                           "size": len(cfg)}, "layers": descs}
    mdata = json.dumps(manifest).encode()
    md = _blob(root, mdata)
    (root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": md, "size": len(mdata)}]}))
    return root


def os_layer(os_release: bytes = OS_RELEASE, issue: bytes = b"AUTHORIZED USE ONLY\n") -> list[tuple]:
    return [("dir", "etc"), ("file", "etc/os-release", os_release), ("file", "etc/issue", issue),
            ("dir", "bin"), ("file", "bin/sh", b"#!fake", 0o755)]


BENCHMARKS_YAML = f"""
candidates:
  - key: test-posture
    family: postureos
    source: custom
    title: Posture test benchmark
    match: {{os.id: "^postureos$"}}
    datastreams: ["posture-test-ds.xml"]
    profiles: ["{TEST_PROFILE}"]
"""
