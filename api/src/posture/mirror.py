"""Mirror-then-scan (DESIGN §4.3): skopeo copy each digest into the in-cluster registry."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field

from .config import Settings
from .images import ImageRef, mirror_target, rewrite_registry, safe_ref_arg
from .logs import get_logger
from .scanners.base import run_proc, scratch_dir, tail

log = get_logger(__name__)

POLICY = {"default": [{"type": "insecureAcceptAnything"}]}
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass
class ScanTarget:
    ref: str  # what the scanners pull (digest-pinned `dest@sha256:..` when mirrored)
    insecure: bool  # plain-http / unverified TLS registry
    mirrored: bool
    source_ref: str
    warnings: list[str] = field(default_factory=list)
    # True when the mirrored manifest's digest was checked against the source digest (the
    # source's own digest, or one of the platform manifests of the source index).
    digest_verified: bool = False
    mirror_digest: str | None = None


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _child_digests(manifest: bytes) -> set[str]:
    """Digests of the platform manifests listed by an OCI index / Docker manifest list."""
    try:
        doc = json.loads(manifest)
    except ValueError:
        return set()
    if not isinstance(doc, dict):
        return set()
    return {str(m.get("digest", "")).lower() for m in doc.get("manifests") or [] if isinstance(m, dict)}


class Mirror:
    """skopeo copy into the mirror, then scan `dest@<digest>` (security review C2).

    The mirror registry is a trust anchor: anyone who can push to it could otherwise replace
    the content behind a tag. So the scanners never pull a mirror *tag*: they pull the digest
    skopeo reports for the copy (`--digestfile`), and a cached copy is reused only when its
    manifest digest matches the source digest (or one of the source index's platform manifests).
    """

    VERIFIED_FILE = "mirror-verified.json"
    VERIFIED_MAX = 5000

    def __init__(self, settings: Settings):
        self.s = settings
        self._verified: dict[str, str] | None = None
        self.registry = settings.mirror_registry
        self.rewrite = settings.rewrite_map
        self.insecure_registries = {self.registry, *self.rewrite.values()} if settings.mirror_insecure else set()
        self._policy_path: str | None = None
        # MIRROR_MODE (architecture review M7): registry (this class) | local (per-digest OCI
        # layout, posture.image_cache) | off (scan the original ref)
        self.mode = settings.effective_mirror_mode
        self.cache = None
        if self.mode == "local":
            from .image_cache import LocalImageCache

            self.cache = LocalImageCache(settings, self)

    def release(self, target: ScanTarget) -> None:
        """A scan finished reading `target` (unpins a local cache layout for LRU eviction)."""
        if self.cache is not None and target.ref.startswith("oci-dir:"):
            self.cache.release(target.ref)

    def policy_path(self) -> str:
        if self._policy_path and os.path.exists(self._policy_path):
            return self._policy_path
        d = os.path.join(self.s.cache_dir, "skopeo")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(POLICY, fh)
        self._policy_path = path
        return path

    def _auth_args(self, flag: str) -> list[str]:
        f = self.s.registry_auth_file
        return [flag, f] if f and os.path.exists(f) else []

    def plan(self, ref: ImageRef) -> tuple[ImageRef, bool, bool]:
        """-> (source ref after rewrite, source insecure, already in mirror registry)."""
        src = rewrite_registry(ref, self.rewrite)
        src_insecure = src.registry in self.insecure_registries
        return src, src_insecure, src.registry == self.registry

    async def exists(self, dest: str, insecure: bool) -> bool:
        return await self._raw_bytes(dest, insecure) is not None

    # ------------------------------------------------------------ verified copies
    def _verified_path(self) -> str:
        return os.path.join(self.s.cache_dir, "skopeo", self.VERIFIED_FILE)

    def _verified_map(self) -> dict[str, str]:
        """source digest -> manifest digest of the mirror copy, recorded when skopeo copied the
        source *by digest* (skopeo verified the pulled manifest against it) or when the copy was
        found in the source index. Lives on the worker's cache volume, not in the mirror registry
        (which is not trusted), so a later check needs no upstream request (Docker Hub 429)."""
        if self._verified is None:
            try:
                with open(self._verified_path(), encoding="utf-8") as fh:
                    data = json.load(fh)
                self._verified = {str(k): str(v) for k, v in data.items()
                                  if _DIGEST_RE.match(str(k)) and _DIGEST_RE.match(str(v))} \
                    if isinstance(data, dict) else {}
            except (OSError, ValueError):
                self._verified = {}
        return self._verified

    def _record_verified(self, src_digest: str, copy_digest: str | None) -> None:
        m = self._verified_map()
        if copy_digest is None:
            if m.pop(src_digest, None) is None:
                return
        elif m.get(src_digest) == copy_digest:
            return
        else:
            m.pop(src_digest, None)
            m[src_digest] = copy_digest  # insertion order = age; oldest dropped first
            while len(m) > self.VERIFIED_MAX:
                m.pop(next(iter(m)))
        path = self._verified_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(m, fh)
            os.replace(tmp, path)
        except OSError as e:  # best effort: the next check falls back to the source index
            log.warning("mirror.verified_record_failed", error=str(e))

    async def verify_cached(self, dest: str, dest_insecure: bool, src_ref: str, src_insecure: bool,
                            src_digest: str) -> tuple[str | None, str]:
        """-> (digest of the cached copy or None when absent, verdict). Verdicts:
        `match` (the copy is the source manifest), `recorded` (the copy is the platform manifest /
        converted manifest skopeo wrote when it copied this source digest), `child` (listed by the
        source index), `mismatch` (it is not), `unverifiable` (the source index could not be fetched,
        e.g. Docker Hub 429 - not evidence of a mismatch), `absent`.

        Before the record existed every reuse of a multi-arch copy re-fetched the source index; when
        that fetch was rate limited the copy was reported as "did not match source digest" and
        re-copied, which hit the same rate limit (grace scan #43, alpine:3.20 / postgres:16-alpine)."""
        cached = await self._raw_bytes(dest, dest_insecure)
        if cached is None:
            return None, "absent"
        cached_digest = _sha256(cached)
        if cached_digest == src_digest:
            return cached_digest, "match"
        recorded = self._verified_map().get(src_digest)
        if recorded and recorded == cached_digest:
            return cached_digest, "recorded"
        # single-platform copy of a multi-arch source: the copy must be one of the index's children
        source = await self._raw_bytes(src_ref, src_insecure, authfile=True)
        if source is None:
            return cached_digest, "unverifiable"
        if _sha256(source) != src_digest:
            return cached_digest, "mismatch"
        if cached_digest in _child_digests(source):
            self._record_verified(src_digest, cached_digest)
            return cached_digest, "child"
        return cached_digest, "mismatch"

    async def _raw_config(self, ref: str, insecure: bool, authfile: bool = False) -> bytes | None:
        """The image config blob of a (single-platform) manifest ref."""
        return await self._raw_bytes(ref, insecure, authfile, config=True)

    async def _raw_bytes(self, ref: str, insecure: bool, authfile: bool = False, config: bool = False) -> bytes | None:
        """Exact manifest (or, with `config`, image config) bytes (hashing needs the bytes)."""
        argv = [self.s.skopeo_bin, "--policy", self.policy_path(), "inspect", "--raw",
                *(["--config"] if config else []), f"--tls-verify={str(not insecure).lower()}"]
        if authfile:
            argv += self._auth_args("--authfile")
        argv += ["--", f"docker://{safe_ref_arg(ref)}"]
        with tempfile.TemporaryDirectory(dir=scratch_dir(self.s.cache_dir)) as d:
            path = os.path.join(d, "manifest")
            res = await run_proc(argv, 60, stdout_file=path, stdout_max=MAX_MANIFEST_BYTES)
            if res.returncode != 0 or res.timed_out or res.truncated:
                return None
            with open(path, "rb") as fh:
                data = fh.read()
        return data or None

    async def prepare(self, ref: ImageRef, timeout: float = 900) -> ScanTarget:
        src, src_insecure, in_mirror = self.plan(ref)
        source = src.pullable
        if self.mode == "local" and self.cache is not None:
            from .image_cache import prepare_local

            target = await prepare_local(self.cache, ref, source, src_insecure, timeout)
            return target or ScanTarget(source, src_insecure, False, source)
        if in_mirror:
            # e.g. localhost:32000 -> in-cluster registry: already local, scan in place
            return ScanTarget(source, src_insecure, False, source)
        if self.mode == "off" or not self.s.mirror_enabled:
            return ScanTarget(source, src_insecure, False, source)
        dest = mirror_target(ref, self.registry)
        dest_repo = dest.rsplit(":", 1)[0]
        dest_insecure = self.s.mirror_insecure
        warnings: list[str] = []
        try:
            safe_ref_arg(source)
            if ref.digest:
                cached_digest, verdict = await self.verify_cached(dest, dest_insecure, source, src_insecure,
                                                                  ref.digest)
                if cached_digest and verdict in ("match", "recorded", "child"):
                    return ScanTarget(f"{dest_repo}@{cached_digest}", dest_insecure, True, source,
                                      digest_verified=True, mirror_digest=cached_digest)
                if verdict == "mismatch":
                    log.warning("mirror.digest_mismatch", ref=source, dest=dest, cached=cached_digest,
                                expected=ref.digest)
                    self._record_verified(ref.digest, None)
                    warnings.append(f"mirror copy {dest} did not match source digest {ref.digest}; re-copied")
                elif verdict == "unverifiable":
                    log.warning("mirror.unverifiable", ref=source, dest=dest, cached=cached_digest)
                    warnings.append(f"mirror copy {dest} could not be verified (source manifest of {ref.digest} "
                                    "unavailable, e.g. registry rate limit); re-copied")
            with tempfile.TemporaryDirectory(dir=scratch_dir(self.s.cache_dir)) as d:
                digestfile = os.path.join(d, "digest")
                argv = [self.s.skopeo_bin, "--policy", self.policy_path(), "copy", "--retry-times", "2",
                        f"--src-tls-verify={str(not src_insecure).lower()}",
                        f"--dest-tls-verify={str(not dest_insecure).lower()}",
                        "--digestfile", digestfile,
                        *self._auth_args("--src-authfile")]
                if self.s.mirror_all_platforms:
                    argv.append("--all")
                argv += ["--", f"docker://{source}", f"docker://{dest}"]
                res = await run_proc(argv, timeout)
                copied = ""
                if os.path.exists(digestfile):
                    with open(digestfile, encoding="utf-8") as fh:
                        copied = fh.read(200).strip().lower()
        except Exception as e:  # noqa: BLE001
            return ScanTarget(source, src_insecure, False, source,
                              [*warnings, f"mirror failed ({e}); scanned original ref"])
        if res.timed_out or res.returncode != 0:
            err = "timed out" if res.timed_out else tail(res.stderr or res.stdout, 300)
            log.warning("mirror.failed", ref=source, error=err)
            return ScanTarget(source, src_insecure, False, source,
                              [*warnings, f"mirror failed: {err}; scanned original ref"])
        if not _DIGEST_RE.match(copied):
            log.warning("mirror.no_digest", ref=source, dest=dest)
            return ScanTarget(source, src_insecure, False, source,
                              [*warnings, "mirror copy reported no digest; scanned original ref"])
        log.info("mirror.copied", ref=source, dest=dest, digest=copied, duration_ms=res.duration_ms)
        if ref.digest:
            self._record_verified(ref.digest, copied)
        # skopeo pulled the source by digest (it verifies the manifest against it), so the copy is
        # the source content; with no source digest (tag only) it is pinned but not verified.
        return ScanTarget(f"{dest_repo}@{copied}", dest_insecure, True, source, warnings,
                          digest_verified=bool(ref.digest), mirror_digest=copied)
