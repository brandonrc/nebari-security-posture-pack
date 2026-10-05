"""Security review C2: the mirror copy is scanned by digest and a cached copy is verified."""

from __future__ import annotations

import hashlib
import json

from posture.config import Settings
from posture.images import parse_image_ref
from posture.mirror import Mirror

# ------------------------------------------------------------------ digest-pinned mirror (C2)
D = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()  # noqa: E731

PLATFORM = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "config": {"digest": "sha256:" + "c" * 64}}).encode()
INDEX = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [{"digest": D(PLATFORM), "platform": {"os": "linux", "architecture": "amd64"}}]}
                   ).encode()
FORGED = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "f" * 64}}).encode()

FAKE_SKOPEO = r'''#!/usr/bin/env python3
import json, os, sys
store = os.environ.get("FAKE_STORE") or sys.argv[0] + ".store"
db = json.load(open(store)) if os.path.exists(store) else {}
args = sys.argv[1:]
open(store + ".log", "a").write(json.dumps(args) + "\n")
refs = [a[len("docker://"):] for a in args if a.startswith("docker://")]
if "inspect" in args:
    ref = refs[0]
    if ref not in db:
        sys.stderr.write("manifest unknown\n"); sys.exit(1)
    sys.stdout.buffer.write(bytes.fromhex(db[ref])); sys.exit(0)
if "copy" in args:
    src, dst = refs
    df = args[args.index("--digestfile") + 1]
    if src not in db:
        sys.exit(1)
    data = bytes.fromhex(db[src])
    if b'"manifests"' in data:  # single-platform copy: pick the first child
        child = json.loads(data)["manifests"][0]["digest"]
        data = bytes.fromhex(db[src.split("@")[0] + "@" + child])
    import hashlib
    d = "sha256:" + hashlib.sha256(data).hexdigest()
    db[dst] = data.hex()
    db[dst.rsplit(":", 1)[0] + "@" + d] = data.hex()
    json.dump(db, open(store, "w"))
    open(df, "w").write(d)
    sys.exit(0)
sys.exit(2)
'''


def _mirror(tmp_path, store: dict[str, bytes]):
    skopeo = tmp_path / "skopeo"
    skopeo.write_text(FAKE_SKOPEO)
    skopeo.chmod(0o755)
    (tmp_path / "skopeo.store").write_text(json.dumps({k: v.hex() for k, v in store.items()}))
    s = Settings(mirror_mode="registry", skopeo_bin=str(skopeo), cache_dir=str(tmp_path / "cache"), mirror_registry="mirror:5000",
                 mirror_insecure=True, mirror_enabled=True)
    return Mirror(s), tmp_path / "skopeo.store.log"


SRC = "docker.io/acme/app"
DEST_TAG = lambda d: "mirror:5000/posture-mirror/docker.io/acme/app:" + d.replace(":", "-")  # noqa: E731
DEST_REPO = "mirror:5000/posture-mirror/docker.io/acme/app"


async def test_mirror_copies_with_digestfile_and_scans_by_digest(tmp_path):
    m, log = _mirror(tmp_path, {f"{SRC}@{D(INDEX)}": INDEX, f"{SRC}@{D(PLATFORM)}": PLATFORM})
    t = await m.prepare(parse_image_ref(f"{SRC}:1.0@{D(INDEX)}"))
    assert t.mirrored and t.digest_verified and t.ref == f"{DEST_REPO}@{D(PLATFORM)}"
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    copy = next(c for c in calls if "copy" in c)
    assert "--digestfile" in copy and copy[copy.index("--") + 1] == f"docker://{SRC}@{D(INDEX)}"


async def test_mirror_reuses_verified_cached_copy(tmp_path):
    m, log = _mirror(tmp_path, {f"{SRC}@{D(INDEX)}": INDEX, DEST_TAG(D(INDEX)): PLATFORM})
    t = await m.prepare(parse_image_ref(f"{SRC}@{D(INDEX)}"))
    assert t.digest_verified and t.ref == f"{DEST_REPO}@{D(PLATFORM)}" and not t.warnings
    assert not any("copy" in json.loads(line) for line in log.read_text().splitlines())


async def test_mirror_forged_cached_copy_is_recopied(tmp_path):
    """An attacker pushed a clean image to the digest-named mirror tag: it must not be scanned."""
    m, log = _mirror(tmp_path, {f"{SRC}@{D(INDEX)}": INDEX, f"{SRC}@{D(PLATFORM)}": PLATFORM,
                                DEST_TAG(D(INDEX)): FORGED})
    t = await m.prepare(parse_image_ref(f"{SRC}@{D(INDEX)}"))
    assert t.ref == f"{DEST_REPO}@{D(PLATFORM)}" and t.digest_verified
    assert D(FORGED) not in t.ref and any("did not match" in w for w in t.warnings)
    assert any("copy" in json.loads(line) for line in log.read_text().splitlines())


async def test_mirror_single_arch_source_matches_directly(tmp_path):
    m, _ = _mirror(tmp_path, {DEST_TAG(D(PLATFORM)): PLATFORM})
    t = await m.prepare(parse_image_ref(f"{SRC}@{D(PLATFORM)}"))
    assert t.digest_verified and t.ref == f"{DEST_REPO}@{D(PLATFORM)}"


async def test_mirror_tag_only_source_is_pinned_not_verified(tmp_path):
    m, _ = _mirror(tmp_path, {f"{SRC}:1.0": PLATFORM})
    t = await m.prepare(parse_image_ref(f"{SRC}:1.0"))
    assert t.mirrored and not t.digest_verified and t.ref == f"{DEST_REPO}@{D(PLATFORM)}"


async def test_mirror_failure_falls_back_to_source(tmp_path):
    m, _ = _mirror(tmp_path, {})
    t = await m.prepare(parse_image_ref(f"{SRC}@{D(INDEX)}"))
    assert not t.mirrored and t.ref == f"{SRC}@{D(INDEX)}" and t.warnings


# ------------------------------------------------------------------ multi-arch reuse without upstream
# Docker Hub official image: a Docker manifest list (the digest kubelet reports as imageID) whose
# platform entries are Docker schema 2 manifests; skopeo copies the linux/amd64 one into the mirror.
DOCKER_V2 = json.dumps({
    "schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1472,
               "digest": "sha256:" + "a" * 64},
    "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 3623807,
                "digest": "sha256:" + "b" * 64}]}, indent=3).encode()
DOCKER_V2_ARM = DOCKER_V2.replace(b'"size": 1472', b'"size": 1473')
MANIFEST_LIST = json.dumps({
    "schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "manifests": [
        {"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": len(DOCKER_V2),
         "digest": D(DOCKER_V2), "platform": {"architecture": "amd64", "os": "linux"}},
        {"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": len(DOCKER_V2_ARM),
         "digest": D(DOCKER_V2_ARM), "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}}]},
    indent=3).encode()
HUB = "docker.io/library/alpine"
HUB_REPO = "mirror:5000/posture-mirror/docker.io/library/alpine"


def _rate_limit_upstream(tmp_path) -> None:
    """Docker Hub answers 429: every upstream manifest disappears from the fake registry."""
    store = tmp_path / "skopeo.store"
    db = json.loads(store.read_text())
    store.write_text(json.dumps({k: v for k, v in db.items() if not k.startswith("docker.io/")}))


async def test_multiarch_index_copy_is_reused_when_upstream_rate_limited(tmp_path):
    """Regression (grace scan #43): the cached platform-manifest copy of a multi-arch Docker Hub image
    was re-verified against the upstream index on every scan; a 429 on that fetch was reported as
    "did not match source digest; re-copied" and the re-copy hit 429 too."""
    ref = parse_image_ref(f"{HUB}:3.20@{D(MANIFEST_LIST)}")
    m, log = _mirror(tmp_path, {f"{HUB}@{D(MANIFEST_LIST)}": MANIFEST_LIST, f"{HUB}@{D(DOCKER_V2)}": DOCKER_V2,
                                f"{HUB}@{D(DOCKER_V2_ARM)}": DOCKER_V2_ARM})
    first = await m.prepare(ref)
    assert first.digest_verified and first.ref == f"{HUB_REPO}@{D(DOCKER_V2)}" and not first.warnings
    _rate_limit_upstream(tmp_path)
    log.write_text("")
    m2 = Mirror(m.s)  # new process (worker restart): the record lives on the cache volume
    again = await m2.prepare(ref)
    assert again.digest_verified and again.ref == f"{HUB_REPO}@{D(DOCKER_V2)}" and not again.warnings
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert not any("copy" in c for c in calls)
    assert not any(f"docker://{HUB}@{D(MANIFEST_LIST)}" in c for c in calls)  # no upstream request


async def test_multiarch_existing_copy_verified_once_against_index_then_recorded(tmp_path):
    """A copy made before the record existed is checked against the index once, then recorded."""
    m, log = _mirror(tmp_path, {f"{HUB}@{D(MANIFEST_LIST)}": MANIFEST_LIST,
                                DEST_TAG(D(MANIFEST_LIST)).replace("acme/app", "library/alpine"): DOCKER_V2})
    ref = parse_image_ref(f"{HUB}@{D(MANIFEST_LIST)}")
    t = await m.prepare(ref)
    assert t.digest_verified and t.ref == f"{HUB_REPO}@{D(DOCKER_V2)}" and not t.warnings
    _rate_limit_upstream(tmp_path)
    t2 = await Mirror(m.s).prepare(ref)
    assert t2.digest_verified and not t2.warnings
    assert not any("copy" in json.loads(line) for line in log.read_text().splitlines())


async def test_unverifiable_is_not_reported_as_mismatch(tmp_path):
    m, _ = _mirror(tmp_path, {DEST_TAG(D(MANIFEST_LIST)).replace("acme/app", "library/alpine"): DOCKER_V2})
    t = await m.prepare(parse_image_ref(f"{HUB}@{D(MANIFEST_LIST)}"))
    assert not t.mirrored and not any("did not match" in w for w in t.warnings)
    assert any("could not be verified" in w for w in t.warnings)


async def test_recorded_copy_replaced_in_mirror_is_still_rejected(tmp_path):
    """The record pins the digest of the copy: a different manifest pushed to the tag is a mismatch."""
    m, log = _mirror(tmp_path, {f"{HUB}@{D(MANIFEST_LIST)}": MANIFEST_LIST, f"{HUB}@{D(DOCKER_V2)}": DOCKER_V2})
    ref = parse_image_ref(f"{HUB}@{D(MANIFEST_LIST)}")
    await m.prepare(ref)
    store = tmp_path / "skopeo.store"
    db = json.loads(store.read_text())
    db[DEST_TAG(D(MANIFEST_LIST)).replace("acme/app", "library/alpine")] = FORGED.hex()
    store.write_text(json.dumps(db))
    t = await Mirror(m.s).prepare(ref)
    assert t.ref == f"{HUB_REPO}@{D(DOCKER_V2)}" and any("did not match" in w for w in t.warnings)
