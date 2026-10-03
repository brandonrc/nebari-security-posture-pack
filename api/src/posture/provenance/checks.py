"""Signature / SBOM / SLSA provenance checks (DESIGN §12).

A superset of provenance-collector-pack `internal/verify`:

* referrers: OCI 1.1 referrers API, then the `<algo>-<hex>` fallback tag (theirs:
  fallback tag only); predicate types from descriptor annotations
  (`predicateTypes`, ported verbatim).
* BuildKit attestation manifests embedded in the image index
  (`vnd.docker.reference.type=attestation-manifest`), predicate types from the
  attestation manifest's layer annotations (`indexAttestationPredicateTypes`).
* legacy cosign tags: `sha256-<hex>.sig` (signature), `.att` (attestations; the
  DSSE payload is decoded, theirs only greps the envelope), `.sbom` (`cosign attach sbom`).
* signature verification: `cosign verify` (key or keyless) behind `CosignVerifier`.

All registry I/O goes through `registry.Registry`; tests use a fake.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..images import ImageRef
from ..logs import get_logger
from ..images import safe_ref_arg
from ..scanners.base import run_proc, tail
from .registry import Manifest, Registry, RegistryError

log = get_logger(__name__)

ANNO_SIGSTORE_PREDICATE_TYPE = "dev.sigstore.bundle.predicateType"
ANNO_INTOTO_PREDICATE_TYPE = "in-toto.io/predicate-type"
ANNO_DOCKER_REFERENCE_TYPE = "vnd.docker.reference.type"
ATTESTATION_MANIFEST_TYPE = "attestation-manifest"
ANNO_SIGSTORE_BUNDLE_CONTENT = "dev.sigstore.bundle.content"
SIGSTORE_BUNDLE_PREFIX = "application/vnd.dev.sigstore.bundle"
COSIGN_SIG_ARTIFACT = "application/vnd.dev.cosign.artifact.sig.v1+json"

PREDICATE_SPDX = "https://spdx.dev/Document"
PREDICATE_CYCLONEDX = "https://cyclonedx.org/bom"
SLSA_PREDICATES = ("https://slsa.dev/provenance/", "https://in-toto.io/provenance/")

MAX_ATTESTATION_MANIFESTS = 8
MAX_ATT_LAYERS = 16
MAX_PAYLOAD_BYTES = 1024 * 1024


# ---------------------------------------------------------------- pure helpers (ported)
def predicate_types(desc: dict[str, Any]) -> list[str]:
    """Their `predicateTypes`: sigstore / in-toto annotations first, then every other
    non-empty annotation value (some producers use non-standard keys)."""
    ann = desc.get("annotations") or {}
    out: list[str] = []
    if ann.get(ANNO_SIGSTORE_PREDICATE_TYPE):
        out.append(ann[ANNO_SIGSTORE_PREDICATE_TYPE])
    if ann.get(ANNO_INTOTO_PREDICATE_TYPE):
        out.append(ann[ANNO_INTOTO_PREDICATE_TYPE])
    for k, v in ann.items():
        if k in (ANNO_SIGSTORE_PREDICATE_TYPE, ANNO_INTOTO_PREDICATE_TYPE):
            continue
        if v:
            out.append(v)
    return out


def sbom_format_from_predicate(predicate_type: str) -> str:
    if predicate_type.startswith(PREDICATE_SPDX):
        return "spdx"
    if predicate_type.startswith(PREDICATE_CYCLONEDX):
        return "cyclonedx"
    return ""


def is_slsa_predicate(s: str) -> bool:
    return any(s.startswith(p) for p in SLSA_PREDICATES)


def detect_from_content(s: str) -> str:
    if "https://spdx.dev/Document" in s or "SPDXRef-" in s:
        return "spdx"
    if "CycloneDX" in s or "cyclonedx" in s:
        return "cyclonedx"
    return ""


def detect_sbom_format(payload: bytes | str) -> str:
    """Their `detectSBOMFormat`: in-toto predicateType, then predicate body, then raw markers."""
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
    try:
        stmt = json.loads(text)
    except ValueError:
        stmt = None
    if isinstance(stmt, dict) and stmt.get("predicateType"):
        fmt = sbom_format_from_predicate(str(stmt["predicateType"]))
        if fmt:
            return fmt
        pred = stmt.get("predicate")
        if pred:
            f = detect_from_content(json.dumps(pred))
            if f:
                return f
    return detect_from_content(text)


def sbom_format_from_media_type(mt: str) -> str:
    mt = (mt or "").lower()
    if "spdx" in mt:
        return "spdx"
    if "cyclonedx" in mt:
        return "cyclonedx"
    return ""


def dsse_statement(envelope: bytes) -> bytes | None:
    """Decode a DSSE envelope's base64 payload (the in-toto statement)."""
    try:
        env = json.loads(envelope)
        if isinstance(env, dict) and isinstance(env.get("payload"), str):
            return base64.b64decode(env["payload"])
    except (ValueError, TypeError):
        return None
    return None


def digest_tag(digest: str, suffix: str = "") -> str:
    return digest.replace(":", "-", 1) + suffix


# ---------------------------------------------------------------- result types
@dataclass
class SignatureInfo:
    signed: bool = False
    verified: bool = False
    error: str = ""

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"signed": self.signed, "verified": self.verified}
        if self.error:
            out["error"] = self.error
        return out


@dataclass
class SBOMInfo:
    has_sbom: bool = False
    format: str = ""
    source: str = ""  # referrers | index-attestation | cosign-att | cosign-sbom (ours)

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"hasSBOM": self.has_sbom}
        if self.format:
            out["format"] = self.format
        return out


@dataclass
class ProvenanceInfo:
    has_provenance: bool = False
    predicate_type: str = ""
    source: str = ""

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"hasProvenance": self.has_provenance}
        if self.predicate_type:
            out["predicateType"] = self.predicate_type
        return out


@dataclass
class Attestations:
    """Everything the registry tells us about one digest, fetched once."""

    digest: str | None = None
    index: Manifest | None = None
    referrers: list[dict[str, Any]] = field(default_factory=list)
    referrers_source: str = ""  # api | tag | ""
    index_predicates: list[str] = field(default_factory=list)
    sig_tag: bool = False
    att_predicates: list[str] = field(default_factory=list)
    att_payloads: list[bytes] = field(default_factory=list)
    sbom_tag_format: str | None = None  # "" = .sbom tag exists, format unknown
    error: str = ""


def _is_signature_referrer(d: dict[str, Any]) -> bool:
    at = d.get("artifactType") or ""
    ann = d.get("annotations") or {}
    if at == COSIGN_SIG_ARTIFACT:
        return True
    if at.startswith(SIGSTORE_BUNDLE_PREFIX):
        content = ann.get(ANNO_SIGSTORE_BUNDLE_CONTENT)
        if content:
            return content == "message-signature"
        return not ann.get(ANNO_SIGSTORE_PREDICATE_TYPE)
    return False


async def collect_attestations(reg: Registry, ref: ImageRef, *, want_att: bool = True) -> Attestations:
    """Fetch the image index (or manifest), referrers, BuildKit attestation manifests and
    the legacy cosign tags for `ref` (digest preferred). Registry errors land in `.error`;
    a missing referrers index / tag is the common case and not an error."""
    out = Attestations()
    registry, repo = ref.registry, ref.repository
    reference = ref.digest or ref.tag or "latest"
    try:
        top = await reg.get_manifest(registry, repo, reference)
    except RegistryError as e:
        out.error = f"fetching manifest: {e}"
        out.digest = ref.digest
        return out
    if top is None:
        out.error = f"manifest not found: {ref.display}"
        out.digest = ref.digest
        return out
    out.digest = ref.digest or top.digest
    out.index = top
    digest = out.digest
    if not digest:
        return out

    async def _safe(coro, default):
        try:
            return await coro
        except RegistryError as e:
            log.debug("provenance.registry_partial", ref=ref.display, error=str(e))
            return default

    async def _get_if_exists(reference: str) -> Manifest | None:
        # HEAD first: probes for tags that usually do not exist stay cheap, and Docker
        # Hub does not count HEAD requests against its pull rate limit.
        if not await _safe(reg.manifest_exists(registry, repo, reference), False):
            return None
        return await _safe(reg.get_manifest(registry, repo, reference), None)

    # 1. referrers: API first, fallback tag second (theirs: fallback tag only)
    api = await _safe(reg.referrers(registry, repo, digest), None)
    if api:
        out.referrers, out.referrers_source = list(api), "api"
    else:
        fb = await _get_if_exists(digest_tag(digest))
        if fb is not None and fb.manifests:
            out.referrers, out.referrers_source = fb.manifests, "tag"

    # 2. BuildKit attestation manifests inside the index
    if top.is_index:
        atts = [m for m in top.manifests
                if (m.get("annotations") or {}).get(ANNO_DOCKER_REFERENCE_TYPE) == ATTESTATION_MANIFEST_TYPE]
        for m in atts[:MAX_ATTESTATION_MANIFESTS]:
            am = await _safe(reg.get_manifest(registry, repo, m.get("digest", "")), None)
            if am is None:
                continue
            for layer in am.layers:
                pt = (layer.get("annotations") or {}).get(ANNO_INTOTO_PREDICATE_TYPE)
                if pt:
                    out.index_predicates.append(pt)

    # 3. legacy cosign tags
    out.sig_tag = bool(await _safe(reg.manifest_exists(registry, repo, digest_tag(digest, ".sig")), False))
    if want_att:
        att = await _get_if_exists(digest_tag(digest, ".att"))
        if att is not None:
            for layer in att.layers[:MAX_ATT_LAYERS]:
                pts = predicate_types(layer)
                out.att_predicates.extend(pts)
                if not any(sbom_format_from_predicate(p) or is_slsa_predicate(p) for p in pts) and layer.get("digest"):
                    blob = await _safe(reg.get_blob(registry, repo, layer["digest"], MAX_PAYLOAD_BYTES), None)
                    if blob:
                        out.att_payloads.append(dsse_statement(blob) or blob)
        sbom = await _get_if_exists(digest_tag(digest, ".sbom"))
        if sbom is not None:
            out.sbom_tag_format = next((f for f in (sbom_format_from_media_type(layer.get("mediaType", ""))
                                                     for layer in sbom.layers) if f), "")
    return out


def signature_existence(a: Attestations) -> SignatureInfo:
    """Their `checkExistence` (signed, not verified) over legacy `.sig` and sigstore bundles."""
    if a.error and a.index is None:
        return SignatureInfo(error=a.error)
    if a.sig_tag or any(_is_signature_referrer(d) for d in a.referrers):
        return SignatureInfo(signed=True)
    return SignatureInfo(signed=False)


def sbom_info(a: Attestations) -> SBOMInfo:
    """Their OCISBOMDiscoverer path order: referrers, index attestations, cosign `.att`;
    plus `.sbom` tag (ours)."""
    for d in a.referrers:
        for pt in predicate_types(d):
            fmt = sbom_format_from_predicate(pt)
            if fmt:
                return SBOMInfo(True, fmt, "referrers")
    for pt in a.index_predicates:
        fmt = sbom_format_from_predicate(pt)
        if fmt:
            return SBOMInfo(True, fmt, "index-attestation")
    for pt in a.att_predicates:
        fmt = sbom_format_from_predicate(pt)
        if fmt:
            return SBOMInfo(True, fmt, "cosign-att")
    for payload in a.att_payloads:
        fmt = detect_sbom_format(payload)
        if fmt:
            return SBOMInfo(True, fmt, "cosign-att")
    if a.sbom_tag_format is not None:
        return SBOMInfo(True, a.sbom_tag_format, "cosign-sbom")
    return SBOMInfo(False)


def provenance_info(a: Attestations) -> ProvenanceInfo:
    """Their SLSAProvenanceChecker (referrers, index attestations) plus cosign `.att`."""
    for d in a.referrers:
        for pt in predicate_types(d):
            if is_slsa_predicate(pt):
                return ProvenanceInfo(True, pt, "referrers")
    for pt in a.index_predicates:
        if is_slsa_predicate(pt):
            return ProvenanceInfo(True, pt, "index-attestation")
    for pt in a.att_predicates:
        if is_slsa_predicate(pt):
            return ProvenanceInfo(True, pt, "cosign-att")
    for payload in a.att_payloads:
        try:
            stmt = json.loads(payload)
        except ValueError:
            continue
        pt = stmt.get("predicateType") if isinstance(stmt, dict) else None
        if isinstance(pt, str) and is_slsa_predicate(pt):
            return ProvenanceInfo(True, pt, "cosign-att")
    return ProvenanceInfo(False)


# ---------------------------------------------------------------- cosign verification
@dataclass
class CosignConfig:
    public_key: str = ""  # PEM text, file path or KMS URI (cosign --key)
    certificate_identity_regexp: str = ""  # keyless
    certificate_oidc_issuer_regexp: str = ""
    ignore_tlog: bool = True  # theirs: IgnoreTlog=true for key-based verification

    @property
    def enabled(self) -> bool:
        return bool(self.public_key or (self.certificate_identity_regexp and self.certificate_oidc_issuer_regexp))


class CosignVerifier(Protocol):
    async def verify(self, image_ref: str, insecure: bool = False) -> tuple[bool, str]: ...


class CosignCli:
    """`cosign verify` subprocess. Returns (verified, error)."""

    def __init__(self, cfg: CosignConfig, binary: str = "cosign", timeout: float = 120,
                 env: dict[str, str] | None = None):
        self.cfg = cfg
        self.binary = binary
        self.timeout = timeout
        self.env = env or {}
        self._key_path: str | None = None

    def _key_arg(self) -> str:
        k = self.cfg.public_key.strip()
        if "-----BEGIN" in k:
            if self._key_path is None or not os.path.exists(self._key_path):
                fd, path = tempfile.mkstemp(prefix="cosign-", suffix=".pub")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(k + "\n")
                self._key_path = path
            return self._key_path
        return k

    def argv(self, image_ref: str, insecure: bool = False) -> list[str]:
        argv = [self.binary, "verify", "--output", "json"]
        if self.cfg.public_key:
            argv += ["--key", self._key_arg()]
            if self.cfg.ignore_tlog:
                argv.append("--insecure-ignore-tlog=true")
        else:
            argv += ["--certificate-identity-regexp", self.cfg.certificate_identity_regexp,
                     "--certificate-oidc-issuer-regexp", self.cfg.certificate_oidc_issuer_regexp]
        if insecure:
            argv.append("--allow-insecure-registry")
            argv.append("--allow-http-registry")
        argv += ["--", safe_ref_arg(image_ref)]  # security review M2
        return argv

    async def verify(self, image_ref: str, insecure: bool = False) -> tuple[bool, str]:
        env = {"COSIGN_EXPERIMENTAL": "1", **self.env}
        try:
            argv = self.argv(image_ref, insecure)
        except ValueError as e:
            return False, f"verification failed: {e}"
        res = await run_proc(argv, self.timeout, env)
        if res.timed_out:
            return False, f"verification failed: timed out after {int(self.timeout)}s"
        if res.returncode == 0:
            return True, ""
        return False, "verification failed: " + tail(res.stderr or res.stdout, 400)


async def verify_signature(existence: SignatureInfo, verifier: CosignVerifier | None, image_ref: str,
                           insecure: bool = False) -> SignatureInfo:
    """Existence check, then `cosign verify` when a key / keyless identity is configured.
    Unlike theirs a failed verification keeps `signed: true` (the signature exists) and
    reports the failure in `error`."""
    if verifier is None or existence.error or not existence.signed:
        return existence
    ok, err = await verifier.verify(image_ref, insecure)
    return SignatureInfo(True, ok, "" if ok else err)
