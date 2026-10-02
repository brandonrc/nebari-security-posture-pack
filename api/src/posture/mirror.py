"""Mirror-then-scan (DESIGN §4.3): skopeo copy each digest into the in-cluster registry."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .config import Settings
from .images import ImageRef, mirror_target, rewrite_registry
from .logs import get_logger
from .scanners.base import run_proc, tail

log = get_logger(__name__)

POLICY = {"default": [{"type": "insecureAcceptAnything"}]}


@dataclass
class ScanTarget:
    ref: str  # what the scanners pull
    insecure: bool  # plain-http / unverified TLS registry
    mirrored: bool
    source_ref: str
    warnings: list[str] = field(default_factory=list)


class Mirror:
    def __init__(self, settings: Settings):
        self.s = settings
        self.registry = settings.mirror_registry
        self.rewrite = settings.rewrite_map
        self.insecure_registries = {self.registry, *self.rewrite.values()} if settings.mirror_insecure else set()
        self._policy_path: str | None = None

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
        res = await run_proc([self.s.skopeo_bin, "--policy", self.policy_path(), "inspect", "--raw",
                              f"--tls-verify={str(not insecure).lower()}", f"docker://{dest}"], 60)
        return res.returncode == 0

    async def prepare(self, ref: ImageRef, timeout: float = 900) -> ScanTarget:
        src, src_insecure, in_mirror = self.plan(ref)
        source = src.pullable
        if in_mirror:
            # e.g. localhost:32000 -> in-cluster registry: already local, scan in place
            return ScanTarget(source, src_insecure, False, source)
        if not self.s.mirror_enabled:
            return ScanTarget(source, src_insecure, False, source)
        dest = mirror_target(ref, self.registry)
        dest_insecure = self.s.mirror_insecure
        try:
            if ref.digest and await self.exists(dest, dest_insecure):
                return ScanTarget(dest, dest_insecure, True, source)
            argv = [self.s.skopeo_bin, "--policy", self.policy_path(), "copy", "--retry-times", "2",
                    f"--src-tls-verify={str(not src_insecure).lower()}",
                    f"--dest-tls-verify={str(not dest_insecure).lower()}",
                    *self._auth_args("--src-authfile")]
            if self.s.mirror_all_platforms:
                argv.append("--all")
            argv += [f"docker://{source}", f"docker://{dest}"]
            res = await run_proc(argv, timeout, {"TMPDIR": os.environ.get("TMPDIR", "/tmp")})
        except Exception as e:  # noqa: BLE001
            return ScanTarget(source, src_insecure, False, source, [f"mirror failed ({e}); scanned original ref"])
        if res.timed_out or res.returncode != 0:
            err = "timed out" if res.timed_out else tail(res.stderr or res.stdout, 300)
            log.warning("mirror.failed", ref=source, error=err)
            return ScanTarget(source, src_insecure, False, source, [f"mirror failed: {err}; scanned original ref"])
        log.info("mirror.copied", ref=source, dest=dest, duration_ms=res.duration_ms)
        return ScanTarget(dest, dest_insecure, True, source)
