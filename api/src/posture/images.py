"""Image reference parsing, imageID normalization and mirror ref rewriting."""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_REGISTRY = "docker.io"
_DIGEST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[+._-][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$")
_ID_PREFIXES = ("docker-pullable://", "docker://", "containerd://", "cri-o://")


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def name(self) -> str:
        return f"{self.registry}/{self.repository}"

    @property
    def tagged(self) -> str:
        return f"{self.name}:{self.tag or 'latest'}"

    @property
    def display(self) -> str:
        """Human ref: registry/repo:tag (tag omitted when only a digest is known)."""
        if self.tag:
            return f"{self.name}:{self.tag}"
        if self.digest:
            return f"{self.name}@{self.digest}"
        return f"{self.name}:latest"

    @property
    def pullable(self) -> str:
        """Most precise pullable reference (digest wins over tag)."""
        if self.digest:
            return f"{self.name}@{self.digest}"
        return self.tagged

    def with_registry(self, registry: str) -> ImageRef:
        return ImageRef(registry, self.repository, self.tag, self.digest)


def _looks_like_registry(component: str) -> bool:
    return "." in component or ":" in component or component == "localhost"


def parse_image_ref(ref: str) -> ImageRef:
    """Parse a docker-style image reference.

    `alpine` -> docker.io/library/alpine (tag None), `localhost:32000/a:b@sha256:..` etc.
    """
    ref = ref.strip()
    for prefix in _ID_PREFIXES:
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    if not ref:
        raise ValueError("empty image reference")
    digest: str | None = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not _DIGEST_RE.match(digest):
            raise ValueError(f"invalid digest in image reference: {digest!r}")
        digest = digest.lower()
    tag: str | None = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
        if not tag:
            tag = None
    parts = ref.split("/")
    if len(parts) > 1 and _looks_like_registry(parts[0]):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = DEFAULT_REGISTRY, ref
    if registry in ("index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"):
        registry = DEFAULT_REGISTRY
    if registry == DEFAULT_REGISTRY and "/" not in repo:
        repo = f"library/{repo}"
    if not repo or not re.match(r"^[a-z0-9]+(?:[._/-]+[a-z0-9]+|__[a-z0-9]+)*$", repo):
        raise ValueError(f"invalid repository in image reference: {repo!r}")
    return ImageRef(registry=registry.lower(), repository=repo, tag=tag, digest=digest)


def normalize_image_id(image_id: str | None) -> tuple[str | None, str | None]:
    """Normalize a containerStatus.imageID.

    Returns (repo_digest_ref, bare_digest):
      * `docker.io/library/alpine@sha256:..` -> ("docker.io/library/alpine@sha256:..", "sha256:..")
      * `docker-pullable://alpine@sha256:..`  -> same, prefix stripped + normalized
      * `sha256:abc` (local image / config id) -> (None, "sha256:abc")
      * empty -> (None, None)
    """
    if not image_id:
        return None, None
    s = image_id.strip()
    for prefix in _ID_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
    if not s:
        return None, None
    if "@" not in s:
        if _DIGEST_RE.match(s):
            return None, s.lower()
        return None, None
    try:
        ref = parse_image_ref(s)
    except ValueError:
        return None, None
    return f"{ref.name}@{ref.digest}", ref.digest


@dataclass(frozen=True)
class ImageIdentity:
    key: str  # unique image key (registry/repo@sha256:.. or normalized image string)
    ref: ImageRef  # registry/repo + tag (from spec) + digest (from imageID)
    warnings: tuple[str, ...] = ()


def identify_image(image: str, image_id: str | None) -> ImageIdentity:
    """Build the unique image key per DESIGN §4.2 from spec `image` + status `imageID`."""
    warnings: list[str] = []
    try:
        spec = parse_image_ref(image)
    except ValueError:
        spec = ImageRef(DEFAULT_REGISTRY, image.strip() or "unknown", None, None)
        warnings.append("unparseable image reference")
    repo_digest, bare = normalize_image_id(image_id)
    if repo_digest:
        rid = parse_image_ref(repo_digest)
        ref = ImageRef(rid.registry, rid.repository, spec.tag, rid.digest)
        return ImageIdentity(key=repo_digest, ref=ref, warnings=tuple(warnings))
    if spec.digest:
        return ImageIdentity(key=f"{spec.name}@{spec.digest}", ref=spec, warnings=tuple(warnings))
    if bare:
        warnings.append("imageID has no repository digest (locally loaded image); scanned by tag")
    return ImageIdentity(key=spec.tagged, ref=spec, warnings=tuple(warnings))


def rewrite_registry(ref: ImageRef, rewrite: dict[str, str]) -> ImageRef:
    target = rewrite.get(ref.registry)
    return ref.with_registry(target) if target else ref


def mirror_target(ref: ImageRef, mirror_registry: str) -> str:
    """Destination in the mirror registry. A tag derived from the digest keeps one copy
    per digest and stays scannable even when only one platform is copied."""
    repo = f"posture-mirror/{ref.registry.replace(':', '-')}/{ref.repository}"
    if ref.digest:
        algo, hexd = ref.digest.split(":", 1)
        return f"{mirror_registry}/{repo}:{algo}-{hexd}"
    return f"{mirror_registry}/{repo}:{ref.tag or 'latest'}"


def has_mutable_tag(image: str) -> bool:
    """True when the spec image is `:latest` / untagged and not digest-pinned."""
    try:
        ref = parse_image_ref(image)
    except ValueError:
        return True
    if ref.digest:
        return False
    return ref.tag in (None, "latest")
