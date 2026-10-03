"""MIRROR_MODE=local (architecture review M7): per-digest OCI layout cache with digest
verification (security review C2), reuse, LRU eviction, clair skipped outside registry mode."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from types import SimpleNamespace

import pytest

from posture.image_cache import MARKER, LocalImageCache, layout_manifest_digest
from posture.images import parse_image_ref

MANIFEST = json.dumps({"schemaVersion": 2, "config": {"size": 7}, "layers": [{"size": 1000}]}).encode()
M_DIGEST = "sha256:" + hashlib.sha256(MANIFEST).hexdigest()
INDEX = json.dumps({"manifests": [{"digest": M_DIGEST, "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
I_DIGEST = "sha256:" + hashlib.sha256(INDEX).hexdigest()


def fake_skopeo(tmp_path, manifest: bytes = MANIFEST, pad: int = 0):
    """`skopeo copy ... oci:<dir>` -> an OCI layout holding `manifest` (+ `pad` bytes of layer)."""
    (tmp_path / "m.json").write_bytes(manifest)
    script = tmp_path / "skopeo"
    script.write_text(f"""#!/bin/sh
echo "$@" >> {tmp_path}/calls
for a in "$@"; do last="$a"; done
dir="${{last#oci:}}"
mkdir -p "$dir/blobs/sha256"
h=$(sha256sum {tmp_path}/m.json | cut -d' ' -f1)
cp {tmp_path}/m.json "$dir/blobs/sha256/$h"
head -c {pad} /dev/zero > "$dir/blobs/sha256/layer"
printf '{{"schemaVersion":2,"manifests":[{{"digest":"sha256:%s"}}]}}' "$h" > "$dir/index.json"
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


class FakeMirror:
    def __init__(self, raw=None):
        self.raw = raw

    def policy_path(self):
        return "/dev/null"

    def _auth_args(self, flag):
        return []

    async def _raw_bytes(self, ref, insecure, authfile=False):
        return self.raw


def cache(tmp_path, skopeo, max_bytes=10**9, raw=None):
    s = SimpleNamespace(cache_dir=str(tmp_path / "cache"), image_cache_max_bytes=max_bytes, skopeo_bin=skopeo)
    return LocalImageCache(s, FakeMirror(raw))


async def test_copy_verify_and_reuse(tmp_path):
    c = cache(tmp_path, fake_skopeo(tmp_path))
    layout, digest = await c.ensure("docker.io/library/alpine:3", M_DIGEST, False)
    assert digest == M_DIGEST and layout_manifest_digest(layout) == M_DIGEST
    assert layout.name == "sha256-" + M_DIGEST.split(":")[1] and (layout / MARKER).exists()
    calls = (tmp_path / "calls").read_text()
    assert f"docker://docker.io/library/alpine@{M_DIGEST}" in calls  # always pulled by digest
    await c.ensure("docker.io/library/alpine:3", M_DIGEST, False)
    assert len((tmp_path / "calls").read_text().splitlines()) == 1  # once per digest
    # tampered blob -> no longer verifies -> copied again
    blob = layout / "blobs" / "sha256" / M_DIGEST.split(":")[1]
    blob.write_bytes(b"evil")
    assert layout_manifest_digest(layout) is None
    _, d2 = await c.ensure("docker.io/library/alpine:3", M_DIGEST, False)
    assert d2 == M_DIGEST and len((tmp_path / "calls").read_text().splitlines()) == 2


async def test_multiarch_child_must_belong_to_source_index(tmp_path):
    c = cache(tmp_path, fake_skopeo(tmp_path), raw=INDEX)
    layout, digest = await c.ensure("ghcr.io/o/app", I_DIGEST, False)
    assert digest == M_DIGEST and layout.name.endswith(I_DIGEST.split(":")[1])
    other = "sha256:" + "f" * 64  # source index that does not list the copied manifest
    bad = cache(tmp_path / "b", fake_skopeo(tmp_path), raw=INDEX)
    with pytest.raises(RuntimeError, match="not part of source"):
        await bad.ensure("ghcr.io/o/app", other, False)
    assert not bad.layout_dir(other).exists()


async def test_lru_eviction_skips_in_use(tmp_path):
    c = cache(tmp_path, fake_skopeo(tmp_path, pad=4000), max_bytes=6000)
    a, _ = await c.ensure("r/a", M_DIGEST, False)
    c.release(f"oci-dir:{a}")
    m2 = json.dumps({"x": 2, "layers": []}).encode()
    (tmp_path / "x").mkdir()
    c2 = cache(tmp_path, fake_skopeo(tmp_path / "x", m2, 4000), max_bytes=6000)
    d2 = "sha256:" + hashlib.sha256(m2).hexdigest()
    b, _ = await c2.ensure("r/b", d2, False)  # over the cap: a (unused, older) is evicted, b is pinned
    assert not a.exists() and b.exists()
    assert c2.cleanup() == 0  # b alone is over the cap but still in use


async def test_mirror_local_mode_targets(tmp_path):
    from posture.config import Settings
    from posture.mirror import Mirror

    st = Settings(cache_dir=str(tmp_path / "cache"), skopeo_bin=fake_skopeo(tmp_path), mirror_mode="local")
    m = Mirror(st)
    assert m.mode == "local"
    t = await m.prepare(parse_image_ref(f"docker.io/library/alpine@{M_DIGEST}"))
    assert t.ref.startswith("oci-dir:") and t.mirrored and t.digest_verified and t.mirror_digest == M_DIGEST
    assert m.cache._in_use
    m.release(t)
    assert not m.cache._in_use
    tag_only = await m.prepare(parse_image_ref("docker.io/library/alpine:3"))  # no digest: not cached
    assert tag_only.ref == "docker.io/library/alpine:3" and not tag_only.mirrored
    assert Mirror(Settings(mirror_mode="registry", mirror_enabled=False)).mode == "off"
    assert Settings(mirror_mode="bogus").effective_mirror_mode == "local"


def test_worker_skips_clair_outside_registry_mode():
    from posture.app_settings import AppSettings
    from posture.config import Settings
    from posture.worker import Worker

    st = AppSettings()
    w = Worker(Settings(), sessionmaker=None, scanners={"trivy": object(), "grype": object(), "clair": object()},
               mirror=SimpleNamespace(mode="local"))
    assert w.enabled_scanners(st) == ["trivy", "grype"] and w.clair_skipped(st)
    w.mirror = SimpleNamespace(mode="registry")
    assert "clair" in w.enabled_scanners(st)
    w.mirror = object()  # custom mirror without a mode: treated as a registry
    assert "clair" in w.enabled_scanners(st)
