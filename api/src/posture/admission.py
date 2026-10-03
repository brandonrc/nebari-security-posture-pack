"""Scan admission by image size (architecture review M2).

`parallelism` counts images, but memory follows image size (grype holds the unpacked package
catalog: up to ~3.2 GiB per process measured on ray / jupyter images). Images whose compressed
size exceeds `SCAN_MAX_IMAGE_GB` (20) are moved to the end of the scan queue and scanned one at
a time after everything else, with a warning in the scan log. `SCAN_MAX_IMAGE_GB=0` disables
admission (and the manifest probes below).

The size comes from the registry manifest (layers + config, for this platform), probed once
per digest and kept in `images.size_bytes`: one or two manifest GETs for a new digest.
"""

from __future__ import annotations

import json
import platform
from typing import Any

from .images import ImageRef
from .logs import get_logger

log = get_logger(__name__)

_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json")


def _arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(m, m)


def manifest_size(doc: dict[str, Any]) -> int | None:
    """Compressed size of a single-platform image manifest (layers + config)."""
    layers = doc.get("layers")
    if not isinstance(layers, list):
        return None
    total = sum(int(layer.get("size") or 0) for layer in layers if isinstance(layer, dict))
    total += int((doc.get("config") or {}).get("size") or 0)
    return total


def pick_platform(index: dict[str, Any], arch: str | None = None) -> str | None:
    """Digest of the linux/<arch> child of an index (else the first non-attestation child)."""
    arch = arch or _arch()
    children = [m for m in index.get("manifests") or [] if isinstance(m, dict) and m.get("digest")]
    for m in children:
        p = m.get("platform") or {}
        if p.get("os") == "linux" and p.get("architecture") == arch:
            return m["digest"]
    for m in children:
        if (m.get("platform") or {}).get("os") not in (None, "unknown"):
            return m["digest"]
    return children[0]["digest"] if children else None


async def probe_size(mirror: Any, ref: ImageRef) -> int | None:
    """Image size via `mirror._raw_bytes` (skopeo inspect --raw, with the registry auth file).
    None when unknown (no mirror helper, registry error, unparseable manifest)."""
    raw_bytes = getattr(mirror, "_raw_bytes", None)
    plan = getattr(mirror, "plan", None)
    if raw_bytes is None or plan is None:
        return None
    try:
        src, insecure, _ = plan(ref)
        raw = await raw_bytes(src.pullable, insecure, authfile=True)
        if raw is None:
            return None
        doc = json.loads(raw)
        if doc.get("mediaType") in _INDEX_TYPES or "manifests" in doc:
            child = pick_platform(doc)
            if not child:
                return None
            raw = await raw_bytes(f"{src.registry}/{src.repository}@{child}", insecure, authfile=True)
            if raw is None:
                return None
            doc = json.loads(raw)
        return manifest_size(doc)
    except Exception as e:  # noqa: BLE001  (admission is best effort; never fails a scan)
        log.info("admission.size_unknown", ref=ref.display, error=str(e)[:200])
        return None


def order_for_admission(ids: list[int], sizes: dict[int, int | None], max_bytes: int) -> tuple[list[int], list[int]]:
    """-> (scan now in the usual order, deferred: known to exceed `max_bytes`, smallest first)."""
    if max_bytes <= 0:
        return list(ids), []
    now_, later = [], []
    for i in ids:
        (later if (sizes.get(i) or 0) > max_bytes else now_).append(i)
    later.sort(key=lambda i: sizes.get(i) or 0)
    return now_, later
