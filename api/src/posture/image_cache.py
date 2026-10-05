"""Local per-digest OCI layout cache: `MIRROR_MODE=local` (architecture review M7).

The registry mirror (`MIRROR_MODE=registry`) needs an in-cluster, HTTP-reachable registry:
`registry.container-registry.svc:5000` / `localhost:32000` exist on MicroK8s only, and the
mirror copies privately pulled images into a registry the controls engine itself flags as
anonymously readable. `local` instead copies each digest once into the worker's cache volume

    skopeo copy docker://<source>@<digest> oci:$CACHE_DIR/images/sha256-<hex>

and points trivy (`--input <dir>`) and grype (`oci-dir:<dir>`) at the directory, so every image
is pulled once per digest (Docker Hub limits) and daily rescans re-read local layers. Clair
can only pull from a registry, so it is skipped unless `MIRROR_MODE=registry`.

Digest pinning (security review C2, as for the registry mirror): only digest-pinned refs are
cached; the copy's manifest blob must hash to the digest named in the layout's index.json,
and that digest must be the source digest or one of the source index's platform manifests.
A cached layout is re-verified (manifest blob hash, recorded digest) before every reuse.

LRU: `IMAGE_CACHE_MAX_BYTES` (20 GiB) over all layouts, least recently used first, never a
layout a scan is reading.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from .images import ImageRef, parse_image_ref, safe_ref_arg
from .logs import get_logger
from .scanners.base import run_proc, tail

log = get_logger(__name__)

MARKER = ".posture-cache.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _dir_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def layout_manifest_digest(layout: Path) -> str | None:
    """Digest of the (single) manifest in an OCI layout, after checking its blob hashes to it."""
    try:
        index = json.loads((layout / "index.json").read_text())
        manifests = index.get("manifests") or []
        if len(manifests) != 1:
            return None
        digest = str(manifests[0].get("digest", "")).lower()
        algo, _, hexd = digest.partition(":")
        if algo != "sha256" or len(hexd) != 64:
            return None
        blob = layout / "blobs" / "sha256" / hexd
        return digest if _sha256_file(blob) == digest else None
    except (OSError, ValueError):
        return None


MAX_CHILDREN_CHECKED = 16


def _diff_ids(config: bytes) -> tuple[str, ...]:
    try:
        doc = json.loads(config)
        return tuple(str(d).lower() for d in ((doc.get("rootfs") or {}).get("diff_ids") or []))
    except (ValueError, AttributeError):
        return ()


def _blob_set(manifest: bytes) -> tuple[str, tuple[str, ...]] | None:
    """(config digest, layer digests) of an image manifest (Docker schema 2 or OCI), else None.
    The Docker -> OCI conversion rewrites the config blob, so callers compare layers + diff_ids."""
    try:
        doc = json.loads(manifest)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("layers"), list) or not isinstance(doc.get("config"), dict):
        return None
    cfg = str(doc["config"].get("digest") or "").lower()
    layers = tuple(str((x or {}).get("digest") or "").lower() for x in doc["layers"])
    if not cfg or not all(layers):
        return None
    return cfg, layers


def _children(manifest: bytes) -> set[str]:
    try:
        doc = json.loads(manifest)
    except ValueError:
        return set()
    return {str(m.get("digest", "")).lower() for m in (doc.get("manifests") or []) if isinstance(m, dict)}


class LocalImageCache:
    def __init__(self, settings: Any, mirror: Any):
        self.s = settings
        self.mirror = mirror  # posture.mirror.Mirror: policy, auth file, raw manifest fetch
        self.root = Path(settings.cache_dir) / "images"
        self.max_bytes = int(settings.image_cache_max_bytes)
        self._in_use: dict[str, int] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def layout_dir(self, digest: str) -> Path:
        algo, _, hexd = digest.partition(":")
        return self.root / f"{algo}-{hexd}"

    # ---------------------------------------------------------------- reuse
    def _verified(self, layout: Path, source_digest: str) -> str | None:
        """Manifest digest of a complete cached layout when it still verifies, else None."""
        try:
            marker = json.loads((layout / MARKER).read_text())
        except (OSError, ValueError):
            return None
        digest = layout_manifest_digest(layout)
        if not digest or marker.get("sourceDigest") != source_digest or marker.get("manifestDigest") != digest:
            return None
        return digest

    def pin(self, layout: Path) -> None:
        self._in_use[str(layout)] = self._in_use.get(str(layout), 0) + 1
        try:
            os.utime(layout / MARKER)  # LRU clock
        except OSError:
            pass

    def release(self, path: str) -> None:
        key = path[len("oci-dir:"):] if path.startswith("oci-dir:") else path
        n = self._in_use.get(key, 0) - 1
        if n <= 0:
            self._in_use.pop(key, None)
        else:
            self._in_use[key] = n

    # ---------------------------------------------------------------- copy
    async def ensure(self, source: str, source_digest: str, src_insecure: bool,
                     timeout: float = 900) -> tuple[Path, str]:
        """Layout dir + verified manifest digest for `source@source_digest` (copied if needed).
        Raises RuntimeError with a short reason on failure."""
        layout = self.layout_dir(source_digest)
        lock = self._locks.setdefault(str(layout), asyncio.Lock())
        async with lock:
            digest = await asyncio.to_thread(self._verified, layout, source_digest)
            if digest:
                self.pin(layout)
                return layout, digest
            if layout.exists():
                log.warning("image_cache.invalid", layout=str(layout))
                await asyncio.to_thread(shutil.rmtree, layout, True)
            self.root.mkdir(parents=True, exist_ok=True)
            tmp = Path(tempfile.mkdtemp(prefix=".copy-", dir=self.root))
            try:
                src = parse_image_ref(source)
                pinned = f"{src.registry}/{src.repository}@{source_digest}"
                argv = [self.s.skopeo_bin, "--policy", self.mirror.policy_path(), "copy", "--retry-times", "2",
                        f"--src-tls-verify={str(not src_insecure).lower()}",
                        *self.mirror._auth_args("--src-authfile"),
                        "--", f"docker://{safe_ref_arg(pinned)}", f"oci:{tmp / 'layout'}"]
                res = await run_proc(argv, timeout)
                if res.timed_out or res.returncode != 0:
                    raise RuntimeError("timed out" if res.timed_out else tail(res.stderr or res.stdout, 300))
                digest = await asyncio.to_thread(layout_manifest_digest, tmp / "layout")
                if not digest:
                    raise RuntimeError("copied layout has no verifiable manifest")
                if digest != source_digest:  # platform manifest / format conversion
                    copied = await asyncio.to_thread(
                        (tmp / "layout" / "blobs" / "sha256" / digest.split(":", 1)[1]).read_bytes)
                    if not await self._belongs(src, pinned, src_insecure, source_digest, digest, copied,
                                               tmp / "layout"):
                        raise RuntimeError(f"copied manifest {digest} is not part of source {source_digest}")
                size = await asyncio.to_thread(_dir_size, tmp / "layout")
                (tmp / "layout" / MARKER).write_text(json.dumps({
                    "source": source, "sourceDigest": source_digest, "manifestDigest": digest, "sizeBytes": size,
                    "copiedAt": time.time()}))
                os.replace(tmp / "layout", layout)
            finally:
                await asyncio.to_thread(shutil.rmtree, tmp, True)
            log.info("image_cache.copied", ref=source, digest=digest, layout=str(layout), duration_ms=res.duration_ms)
            self.pin(layout)
        await asyncio.to_thread(self.cleanup)
        return layout, digest

    @staticmethod
    def _layout_blob(layout: Path, digest: str) -> bytes | None:
        """A blob of the layout being copied (verified against its digest)."""
        p = layout / "blobs" / "sha256" / digest.split(":", 1)[-1]
        try:
            data = p.read_bytes()
        except OSError:
            return None
        return data if "sha256:" + hashlib.sha256(data).hexdigest() == digest else None

    async def _belongs(self, src: ImageRef, pinned: str, insecure: bool, source_digest: str, digest: str,
                       copied: bytes, layout: Path) -> bool:
        """The copied manifest is the source (or one of its platform manifests): either listed by the
        source index, or - when skopeo converted a Docker schema 2 manifest to OCI for the layout
        (the manifest bytes change, the content-addressed config and layer blobs do not) - it
        references exactly the blobs of the source manifest / of one of the index's children,
        each of which is verified against its digest."""
        raw = await self.mirror._raw_bytes(pinned, insecure, authfile=True)
        if raw is None or "sha256:" + hashlib.sha256(raw).hexdigest() != source_digest:
            return False
        children = _children(raw)
        if digest in children:
            return True
        want = _blob_set(copied)
        if want is None:
            return False
        candidates = [(pinned, raw)] if _blob_set(raw) else []
        for child in sorted(children)[:MAX_CHILDREN_CHECKED]:
            cref = f"{src.registry}/{src.repository}@{child}"
            craw = await self.mirror._raw_bytes(cref, insecure, authfile=True)
            if craw and "sha256:" + hashlib.sha256(craw).hexdigest() == child:
                candidates.append((cref, craw))
        for ref, manifest in candidates:
            have = _blob_set(manifest)
            if have is None or have[1] != want[1]:
                continue
            if have[0] == want[0]:
                return True
            # converted config: the source config (as the registry serves it for the hash-verified
            # manifest) and the copied one must describe the same filesystem layers
            src_cfg = await self.mirror._raw_config(ref, insecure, authfile=True)
            if src_cfg is None or "sha256:" + hashlib.sha256(src_cfg).hexdigest() != have[0]:
                continue
            copied_cfg = self._layout_blob(layout, want[0])
            if copied_cfg is not None and _diff_ids(src_cfg) and _diff_ids(src_cfg) == _diff_ids(copied_cfg):
                return True
        return False

    # ---------------------------------------------------------------- LRU
    def entries(self) -> list[tuple[float, int, Path]]:
        out = []
        if not self.root.exists():
            return out
        for d in self.root.iterdir():
            if not d.is_dir():
                continue
            m = d / MARKER
            try:
                size = int(json.loads(m.read_text()).get("sizeBytes") or 0)
                out.append((m.stat().st_mtime, size, d))
            except (OSError, ValueError):
                if d.name.startswith(".copy-") and time.time() - d.stat().st_mtime > 6 * 3600:
                    shutil.rmtree(d, ignore_errors=True)  # leftover of a crashed copy
        return out

    def cleanup(self) -> int:
        """Evict least recently used layouts until the cache fits IMAGE_CACHE_MAX_BYTES."""
        from . import metrics

        entries = sorted(self.entries())
        total = sum(size for _, size, _ in entries)
        evicted = 0
        for _, size, d in entries:
            if total <= self.max_bytes:
                break
            if self._in_use.get(str(d)):
                continue
            shutil.rmtree(d, ignore_errors=True)
            total -= size
            evicted += 1
            log.info("image_cache.evicted", layout=str(d), size=size)
        metrics.IMAGE_CACHE_BYTES.set(total)
        return evicted


async def prepare_local(cache: LocalImageCache, ref: ImageRef, source: str, src_insecure: bool,
                        timeout: float = 900):
    """ScanTarget for MIRROR_MODE=local, or None when the ref cannot be cached (no digest)."""
    from .mirror import ScanTarget

    if not ref.digest:
        return None
    try:
        layout, digest = await cache.ensure(source, ref.digest, src_insecure, timeout)
    except Exception as e:  # noqa: BLE001
        log.warning("image_cache.failed", ref=source, error=str(e)[:300])
        return ScanTarget(source, src_insecure, False, source,
                          [f"local image cache failed: {str(e)[:200]}; scanned original ref"])
    return ScanTarget(f"oci-dir:{layout}", False, True, source, digest_verified=True, mirror_digest=digest)
