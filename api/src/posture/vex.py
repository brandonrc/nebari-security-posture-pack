"""VEX store (OpenVEX 0.2.0): the pack's own statements plus operator-supplied documents,
matched per image by any of its references and applied to consensus findings in Python.

Sources (later wins on equal timestamps, so an operator statement overrides the pack's):
  1. VEX_BUILTIN_DIR (default /etc/posture/vex, baked into the worker image from api/vex/);
     a source checkout falls back to api/vex/ next to the package;
  2. VEX_DIR (comma separated; the chart mounts scanner.vex.existingConfigMap / extraVex there).

Every `*.json` file directly in those directories is read (ConfigMap `..data` entries are
skipped). A file that does not parse as OpenVEX is logged, counted in `errors` and ignored.

Product matching (`statement.products[].@id` or `identifiers.purl`):
  * `pkg:oci/<name>[@<digest>][?repository_url=<registry>/<repo>&tag=<tag>]`: `<name>` is the
    last path segment of any of the image's repositories; the optional digest, repository_url
    and tag must match too;
  * `pkg:docker/<namespace>/<name>[@<tag|digest>][?repository_url=<registry>]`;
  * a plain image reference (`ghcr.io/org/app`, `ghcr.io/org/app:1.2`, `...@sha256:..`) or a
    bare digest (`sha256:...`);
  * any other purl (`pkg:deb/debian/libxml2`, `pkg:golang/stdlib@1.24.4`) is a *package*
    product: it applies in every image, to findings on that package.
`subcomponents` narrow an image product to findings on those packages (purl type, name and,
when given, version must match the finding). Vulnerability ids match `vulnerability.name`,
`@id` and `aliases`, case-insensitively.

Among several matching statements the newest (`timestamp`, falling back to the document's)
wins, as in the OpenVEX spec; ties go to the later-loaded document.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote

from .images import DEFAULT_REGISTRY, parse_image_ref
from .logs import get_logger

log = get_logger(__name__)

STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
SUPPRESSING = frozenset({"not_affected"})
JUSTIFICATIONS = frozenset({
    "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist",
})
MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_BUILTIN_DIR = "/etc/posture/vex"
_SRC_VEX_DIR = Path(__file__).resolve().parents[2] / "vex"  # api/vex in a source checkout
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# purl type -> scanner package types it can describe (trivy Result.Type, grype artifact.type, clair)
_PURL_PKG_TYPES: dict[str, frozenset[str]] = {
    "deb": frozenset({"deb", "dpkg", "debian", "ubuntu", "os", "os-pkgs", "distroless"}),
    "rpm": frozenset({"rpm", "redhat", "centos", "rocky", "alma", "almalinux", "amazon", "oracle", "fedora",
                      "suse", "sles", "opensuse", "opensuse-leap", "opensuse.leap", "photon", "mariner",
                      "cbl-mariner", "azurelinux", "os", "os-pkgs"}),
    "apk": frozenset({"apk", "alpine", "wolfi", "chainguard", "minimos", "os", "os-pkgs"}),
    "golang": frozenset({"gobinary", "gomod", "go-module", "golang", "go"}),
    "pypi": frozenset({"python-pkg", "python", "pip", "pipenv", "poetry", "uv", "wheel", "egg", "conda"}),
    "npm": frozenset({"node-pkg", "npm", "yarn", "pnpm", "bun"}),
    "maven": frozenset({"jar", "java-archive", "pom", "gradle", "sbt", "maven"}),
    "gem": frozenset({"gemspec", "gem", "bundler"}),
    "cargo": frozenset({"rust-binary", "rust-crate", "cargo"}),
    "nuget": frozenset({"nuget", "dotnet-core", "dotnet-deps", "packages-lock", "dotnet-pkg"}),
    "composer": frozenset({"composer", "composer-vendor", "php-composer", "php-pecl"}),
}


def normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _parse_time(v: Any) -> datetime | None:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(.*)$", s)
    if m:
        s = m.group(1) + (m.group(2) or "")[:7] + m.group(3)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---------------------------------------------------------------- purls
@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict[str, str]


def parse_purl(s: str) -> Purl | None:
    if not isinstance(s, str) or not s.startswith("pkg:"):
        return None
    rest = s[4:].lstrip("/")
    rest = rest.split("#", 1)[0]
    qs = ""
    if "?" in rest:
        rest, qs = rest.split("?", 1)
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 2:
        return None
    typ = parts[0].lower()
    name = unquote(parts[-1])
    ns = "/".join(unquote(p) for p in parts[1:-1])
    quals = {k.lower(): unquote(v) for k, v in parse_qsl(qs, keep_blank_values=True)}
    return Purl(typ, ns, name, unquote(version), quals)


@dataclass(frozen=True)
class PackageMatcher:
    """A package (subcomponent or package product): names compared normalized."""

    names: frozenset[str]
    purl_type: str | None = None
    version: str | None = None

    @classmethod
    def from_id(cls, ident: str) -> PackageMatcher | None:
        p = parse_purl(ident)
        if p is None:
            ident = (ident or "").strip()
            return cls(frozenset({normalize_package(ident)})) if ident else None
        names = {p.name}
        if p.namespace:
            names |= {f"{p.namespace}/{p.name}", f"{p.namespace}:{p.name}"}
        return cls(frozenset(normalize_package(n) for n in names), p.type, p.version or None)

    def matches(self, package: str, pkg_type: str | None, installed_version: str | None) -> bool:
        if normalize_package(package) not in self.names:
            return False
        if self.version and installed_version and self.version != installed_version:
            return False
        if self.version and not installed_version:
            return False
        compat = _PURL_PKG_TYPES.get(self.purl_type or "")
        t = (pkg_type or "").strip().lower()
        return not (compat and t and t not in compat)


# ---------------------------------------------------------------- image identity
def _repo_key(registry: str, repository: str) -> str:
    registry = registry.lower()
    if registry in ("index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"):
        registry = DEFAULT_REGISTRY
    if registry == DEFAULT_REGISTRY and "/" not in repository:
        repository = f"library/{repository}"
    return f"{registry}/{repository}".lower()


@dataclass
class ImageIdentity:
    """Every name an image is known by: the original ref, the inventory key, its tags, the
    rewritten / mirrored source, and its digests (index and platform manifest)."""

    repos: set[str] = field(default_factory=set)  # registry/repository
    names: set[str] = field(default_factory=set)  # last path segment of each repository
    tags: set[str] = field(default_factory=set)
    digests: set[str] = field(default_factory=set)
    refs: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, refs: Iterable[str | None], digests: Iterable[str | None] = (),
           tags: Iterable[str | None] = ()) -> ImageIdentity:
        ident = cls()
        for r in refs:
            if not r or r.startswith(("oci-dir:", "oci:")):
                continue
            try:
                ref = parse_image_ref(r)
            except ValueError:
                continue
            ident.add(ref.registry, ref.repository, ref.tag, ref.digest)
            ident.refs.append(r)
        for d in digests:
            if d and _DIGEST_RE.match(d.lower()):
                ident.digests.add(d.lower())
        for t in tags:
            if t and ":" not in t and "/" not in t and "@" not in t:
                ident.tags.add(t)
            elif t:
                try:
                    ref = parse_image_ref(t)
                    ident.add(ref.registry, ref.repository, ref.tag, ref.digest)
                except ValueError:
                    pass
        return ident

    def add(self, registry: str, repository: str, tag: str | None, digest: str | None) -> None:
        self.repos.add(_repo_key(registry, repository))
        self.names.add(repository.rsplit("/", 1)[-1].lower())
        if tag:
            self.tags.add(tag)
        if digest:
            self.digests.add(digest.lower())


@dataclass(frozen=True)
class ImageMatcher:
    name: str | None = None  # last path segment
    repo: str | None = None  # registry/repository
    tag: str | None = None
    digest: str | None = None

    def matches(self, ident: ImageIdentity) -> bool:
        if self.repo and self.repo not in ident.repos:
            return False
        if self.name and self.name not in ident.names:
            return False
        if self.tag and self.tag not in ident.tags:
            return False
        return not (self.digest and self.digest not in ident.digests)


def _strip_scheme(url: str) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip(), flags=re.I).rstrip("/")


def image_matcher(ident: str) -> ImageMatcher | None:
    """ImageMatcher for an OCI/docker purl, a plain image reference or a bare digest; None for
    anything else (package products)."""
    ident = (ident or "").strip()
    if not ident:
        return None
    if _DIGEST_RE.match(ident.lower()):
        return ImageMatcher(digest=ident.lower())
    p = parse_purl(ident)
    if p is not None:
        ver = p.version.lower()
        digest = ver if _DIGEST_RE.match(ver) else None
        if p.type == "oci":
            repo = None
            if p.qualifiers.get("repository_url"):
                try:
                    r = parse_image_ref(_strip_scheme(p.qualifiers["repository_url"]))
                    repo = _repo_key(r.registry, r.repository)
                except ValueError:
                    return None
            return ImageMatcher(name=p.name.lower(), repo=repo, tag=p.qualifiers.get("tag") or None, digest=digest)
        if p.type == "docker":
            registry = _strip_scheme(p.qualifiers.get("repository_url") or DEFAULT_REGISTRY)
            repository = f"{p.namespace}/{p.name}" if p.namespace else p.name
            tag = p.qualifiers.get("tag") or (p.version if p.version and not digest else None)
            return ImageMatcher(name=p.name.lower(), repo=_repo_key(registry, repository.lower()), tag=tag,
                                digest=digest)
        return None
    try:
        r = parse_image_ref(ident)
    except ValueError:
        return None
    return ImageMatcher(name=r.repository.rsplit("/", 1)[-1].lower(), repo=_repo_key(r.registry, r.repository),
                        tag=r.tag, digest=r.digest)


# ---------------------------------------------------------------- statements
@dataclass(frozen=True)
class Product:
    image: ImageMatcher | None  # None: a package product (applies in every image)
    package: PackageMatcher | None  # set for package products
    subcomponents: tuple[PackageMatcher, ...] = ()

    def applies_to(self, ident: ImageIdentity) -> bool:
        return self.image is None or self.image.matches(ident)

    def covers(self, package: str, pkg_type: str | None, installed_version: str | None) -> bool:
        if self.image is None:
            return bool(self.package and self.package.matches(package, pkg_type, installed_version))
        if not self.subcomponents:
            return True
        return any(s.matches(package, pkg_type, installed_version) for s in self.subcomponents)


@dataclass(frozen=True)
class Statement:
    vuln_ids: frozenset[str]
    status: str
    products: tuple[Product, ...]
    justification: str | None
    detail: str | None  # impact_statement / action_statement / status_notes
    timestamp: datetime
    source: str  # file name + document @id
    order: int

    @property
    def suppresses(self) -> bool:
        return self.status in SUPPRESSING


@dataclass(frozen=True)
class VexDecision:
    status: str
    justification: str | None
    detail: str | None
    source: str

    @property
    def suppressed(self) -> bool:
        return self.status in SUPPRESSING


def _product(p: Any) -> Product | None:
    if isinstance(p, str):
        p = {"@id": p}
    if not isinstance(p, dict):
        return None
    ids = [p.get("@id")] + [((p.get("identifiers") or {}).get(k)) for k in ("purl",)]
    ids = [i for i in ids if isinstance(i, str) and i.strip()]
    if not ids:
        return None
    subs = []
    for s in p.get("subcomponents") or []:
        sid = s if isinstance(s, str) else (s.get("@id") or (s.get("identifiers") or {}).get("purl")
                                            if isinstance(s, dict) else None)
        m = PackageMatcher.from_id(sid) if sid else None
        if m:
            subs.append(m)
    for ident in ids:
        im = image_matcher(ident)
        if im is not None:
            return Product(im, None, tuple(subs))
    pm = PackageMatcher.from_id(ids[0]) if parse_purl(ids[0]) else None
    return Product(None, pm, ()) if pm else None


def parse_openvex(doc: Any, source: str, order: int = 0) -> list[Statement]:
    """Statements of an OpenVEX document. Raises ValueError when it is not OpenVEX."""
    if not isinstance(doc, dict) or not isinstance(doc.get("statements"), list):
        raise ValueError("not an OpenVEX document (no statements[])")
    ctx = str(doc.get("@context") or "")
    if ctx and "openvex" not in ctx:
        raise ValueError(f"unsupported @context {ctx[:80]!r}")
    doc_ts = _parse_time(doc.get("timestamp")) or _EPOCH
    label = source + (f" ({doc['@id']})" if isinstance(doc.get("@id"), str) else "")
    out: list[Statement] = []
    for i, st in enumerate(doc["statements"]):
        if not isinstance(st, dict):
            continue
        status = str(st.get("status") or "").strip().lower()
        if status not in STATUSES:
            log.warning("vex.statement_skipped", source=source, index=i, reason=f"status {status!r}")
            continue
        vuln = st.get("vulnerability")
        if isinstance(vuln, str):
            vuln = {"name": vuln}
        vuln = vuln or {}
        vids = {str(x).strip().upper() for x in [vuln.get("name"), vuln.get("@id"), *(vuln.get("aliases") or [])]
                if isinstance(x, str) and x.strip()}
        products = tuple(p for p in (_product(x) for x in st.get("products") or []) if p is not None)
        if not vids or not products:
            log.warning("vex.statement_skipped", source=source, index=i, reason="no vulnerability or product")
            continue
        just = st.get("justification")
        detail = st.get("impact_statement") or st.get("action_statement") or st.get("status_notes")
        out.append(Statement(
            vuln_ids=frozenset(vids), status=status, products=products,
            justification=str(just) if just else None, detail=str(detail)[:4000] if detail else None,
            timestamp=_parse_time(st.get("timestamp")) or _parse_time(st.get("last_updated")) or doc_ts,
            source=label, order=order * 100000 + i,
        ))
    return out


class ImageVex:
    """The statements applicable to one image, indexed by vulnerability id."""

    def __init__(self, items: list[tuple[Statement, Product]]):
        self.by_vuln: dict[str, list[tuple[Statement, Product]]] = {}
        for st, p in items:
            for v in st.vuln_ids:
                self.by_vuln.setdefault(v, []).append((st, p))

    def __len__(self) -> int:
        return sum(len(v) for v in self.by_vuln.values())

    def decide(self, vuln_id: str, package: str, pkg_type: str | None = None,
               installed_version: str | None = None) -> VexDecision | None:
        best: Statement | None = None
        for st, p in self.by_vuln.get((vuln_id or "").upper(), ()):
            if not p.covers(package, pkg_type, installed_version):
                continue
            if best is None or (st.timestamp, st.order) > (best.timestamp, best.order):
                best = st
        if best is None:
            return None
        return VexDecision(best.status, best.justification, best.detail, best.source)


class VexStore:
    def __init__(self, dirs: Iterable[str] = ()):
        self.dirs = [d for d in dirs if d]
        self.statements: list[Statement] = []
        self.files: list[str] = []  # documents that parsed (handed to trivy/grype --vex)
        self.errors: dict[str, str] = {}
        self._sig: tuple | None = None
        self.load()

    @classmethod
    def from_settings(cls, s: Any) -> VexStore:
        dirs: list[str] = []
        builtin = getattr(s, "vex_builtin_dir", DEFAULT_BUILTIN_DIR) or ""
        if builtin and os.path.isdir(builtin):
            dirs.append(builtin)
        elif builtin == DEFAULT_BUILTIN_DIR and _SRC_VEX_DIR.is_dir():
            dirs.append(str(_SRC_VEX_DIR))  # source checkout / tests
        dirs += list(getattr(s, "vex_dir", None) or [])
        return cls(dirs)

    def _candidates(self) -> list[Path]:
        out: list[Path] = []
        for d in self.dirs:
            p = Path(d)
            try:
                names = sorted(os.listdir(p))
            except OSError:
                continue
            out += [p / n for n in names if n.endswith(".json") and not n.startswith(".")]
        return out

    def _signature(self) -> tuple:
        sig = []
        for f in self._candidates():
            try:
                st = f.stat()
                sig.append((str(f), st.st_mtime_ns, st.st_size))
            except OSError:
                continue
        return tuple(sig)

    def load(self) -> None:
        statements: list[Statement] = []
        files: list[str] = []
        errors: dict[str, str] = {}
        for order, f in enumerate(self._candidates()):
            try:
                if f.stat().st_size > MAX_FILE_BYTES:
                    raise ValueError(f"larger than {MAX_FILE_BYTES} bytes")
                doc = json.loads(f.read_text(encoding="utf-8"))
                sts = parse_openvex(doc, f.name, order)
            except (OSError, ValueError) as e:
                errors[str(f)] = str(e)[:300]
                log.warning("vex.file_rejected", file=str(f), error=str(e)[:300])
                continue
            statements += sts
            files.append(str(f))
        self.statements, self.files, self.errors = statements, files, errors
        self._sig = self._signature()
        log.info("vex.loaded", dirs=self.dirs, files=len(files), statements=len(statements), errors=len(errors))

    def reload_if_changed(self) -> bool:
        """Re-read the directories when a file was added, removed or changed (ConfigMap updates)."""
        if self._signature() == self._sig:
            return False
        self.load()
        return True

    def for_image(self, ident: ImageIdentity) -> ImageVex:
        return ImageVex([(st, p) for st in self.statements for p in st.products if p.applies_to(ident)])
